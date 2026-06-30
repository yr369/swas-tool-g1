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

# Each entry: a regex that, if it matches a line of tool output, marks
# that line as noise to be dropped. Keep these conservative - it's much
# worse to silently drop a real finding than to let a little noise
# through for a human to dismiss.
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


def filter_noise(tool_name: str, raw_output: str) -> tuple[str, int]:
    """
    Given a tool's raw multi-line output, removes lines matching known
    noisy patterns for that tool. Returns (cleaned_output, lines_removed).

    If a tool has no known patterns, returns the output unchanged - this
    is a deliberate allow-list approach, not a deny-list: we only filter
    patterns we're confident about, rather than guessing.
    """
    patterns = _NOISY_PATTERNS.get(tool_name, [])
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
