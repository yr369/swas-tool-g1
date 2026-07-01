"""
fp_filter.py - static, zero-cost false-positive filtering.

Plain-language: before a tool's output becomes a "finding" worth your
attention, check it against known noisy patterns for that specific tool.
This is pure pattern-matching (no AI call, no cost, instant) based on
well-documented, publicly-known false-positive behaviors of each tool.

This does NOT replace human review - it just stops obviously-noisy
results from ever reaching the findings table at all, so your review
queue and any future AI triage step only see things worth a look.
"""

import re

# Universal patterns: well-documented false-positive behaviors of these
# specific tools, true regardless of which program you're scanning.
_NOISY_PATTERNS: dict[str, list[re.Pattern]] = {
    "nuclei": [
        # WAF/CDN block pages frequently trigger generic detection
        # templates without being a real vulnerability.
        re.compile(r"waf-detect", re.IGNORECASE),
    ],
    "dalfox": [
        # dalfox often flags reflected params that are HTML-encoded and
        # therefore not actually exploitable - a well-known FP pattern.
        re.compile(r"reflected.*encoded", re.IGNORECASE),
    ],
}

# "Strict" patterns: NOT universal false positives - these are real,
# technically-correct findings that some programs explicitly state they
# will NOT pay for (e.g. JustEatTakeaway's brief: missing security
# headers, SSL/TLS config, open redirects, subdomain takeover without
# proven exploitation are all explicitly excluded). Filtering these out
# globally would be wrong for OTHER programs that DO want them - this is
# opt-in per scan via the strict_mode flag, not a universal rule.
_STRICT_PATTERNS: dict[str, list[re.Pattern]] = {
    "nuclei": [
        re.compile(r"missing-security-headers", re.IGNORECASE),
        re.compile(r"http-missing-security-headers", re.IGNORECASE),
        re.compile(r"insecure-cipher-suite", re.IGNORECASE),
        re.compile(r"ssl[-_]?(config|cert)", re.IGNORECASE),
        re.compile(r"open-redirect", re.IGNORECASE),
        re.compile(r"subdomain-takeover", re.IGNORECASE),
        re.compile(r"weak-cipher", re.IGNORECASE),
        re.compile(r"dns-(spf|dmarc)", re.IGNORECASE),
    ],
}


def filter_noise(tool_name: str, raw_output: str, strict_mode: bool = False) -> tuple[str, int]:
    """
    Given a tool's raw multi-line output, removes lines matching known
    noisy patterns for that tool. Returns (cleaned_output, lines_removed).

    strict_mode (default False): when True, ALSO filters findings that
    are technically real but commonly excluded by program rules (missing
    headers, SSL/TLS config, open redirects, etc.) - turn this on per-
    project for programs whose brief explicitly says these aren't
    eligible, so they never reach your review queue or waste an AI
    triage call. Leave off (default) for programs that do want this kind
    of finding - it's a real, valid security observation for many.

    If a tool has no known patterns, returns the output unchanged - this
    is a deliberate allow-list approach, not a deny-list: we only filter
    patterns we're confident about, rather than guessing.
    """
    patterns = list(_NOISY_PATTERNS.get(tool_name, []))
    if strict_mode:
        patterns += _STRICT_PATTERNS.get(tool_name, [])

    if not patterns:
        return raw_output, 0

    lines = raw_output.splitlines()
    kept_lines = []
    removed_count = 0

    for line in lines:
        if any(p.search(line) for p in patterns):
            removed_count += 1
        else:
            kept_lines.append(line)

    return "\n".join(kept_lines), removed_count
