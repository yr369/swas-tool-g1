"""
Manual verification harness for gate.py's outcome-history awareness.

Needs a real Postgres with the finding_outcomes/findings schema applied
(same schema family as the other manual harnesses). Run from `backend/`:

    export DATABASE_URL="postgresql://postgres:testpass@localhost/swas_test"
    python3 -m app.test_gate_outcome_context_manual

No GEMINI_API_KEY needed - this exercises the real DB lookup
(triage.fetch_signature_stats, shared with triage.py) and the real
`_format_gate_outcome_context` calibration logic directly, without going
through an actual model call. That's deliberate: the thing worth
verifying here is the threshold logic and the exact wording gate.py
would inject, not the LLM's response to it.

What this proves:
  1. A signature with NO history gets no outcome_context injected -
     _format_gate_outcome_context returns "" - so a brand-new
     detection's gate behavior is byte-for-byte unchanged.
  2. A signature with a MIXED history (some rejected, one accepted)
     gets no outcome_context either - one accepted outcome is enough to
     prove the pattern is sometimes real, so gate.py stays silent and
     leaves the call to triage, as designed.
  3. A signature with fewer than 3 outcomes gets no outcome_context,
     even if 100% rejected - too small a sample to treat as a pattern.
  4. A signature with >=3 outcomes, ALL rejected/not_applicable, ZERO
     accepted/informative DOES get the outcome_context injected, and it
     says the right thing (mentions the exact counts, frames it as
     signal-quality not severity).
"""
import asyncio
import os

import asyncpg

from . import gate


async def _seed_outcomes(conn, signature: str, outcomes: list[str]):
    for outcome in outcomes:
        await conn.execute(
            "INSERT INTO finding_outcomes (signature, outcome, platform) VALUES ($1, $2, 'hackerone')",
            signature, outcome,
        )


async def main():
    database_url = os.environ["DATABASE_URL"]
    conn = await asyncpg.connect(database_url)
    from . import triage as triage_module

    try:
        # 1. No history at all.
        sig_none = "test-tool:no_history_vuln:website"
        stats = await triage_module.fetch_signature_stats(conn, sig_none)
        ctx = gate._format_gate_outcome_context(stats)
        assert ctx == "", f"expected no context for brand-new signature, got: {ctx!r}"
        print("PASS (1/4): brand-new signature with no history gets no outcome_context")

        # 2. Mixed history: 2 rejected + 1 accepted.
        sig_mixed = "test-tool:mixed_history_vuln:website"
        await _seed_outcomes(conn, sig_mixed, ["rejected", "rejected", "accepted"])
        stats = await triage_module.fetch_signature_stats(conn, sig_mixed)
        ctx = gate._format_gate_outcome_context(stats)
        assert ctx == "", f"expected no context for mixed history (has an accepted), got: {ctx!r}"
        print("PASS (2/4): mixed history (any accepted/informative present) gets no outcome_context")

        # 3. Small sample, all rejected, but below the size-3 threshold.
        sig_small = "test-tool:small_sample_vuln:website"
        await _seed_outcomes(conn, sig_small, ["rejected", "rejected"])
        stats = await triage_module.fetch_signature_stats(conn, sig_small)
        ctx = gate._format_gate_outcome_context(stats)
        assert ctx == "", f"expected no context for a 2-sample history, got: {ctx!r}"
        print("PASS (3/4): 100%-rejected but only 2 samples still gets no outcome_context (too small)")

        # 4. Clean negative history, sample size >= 3.
        sig_dead = "test-tool:dead_pattern_vuln:website"
        await _seed_outcomes(conn, sig_dead, ["rejected", "rejected", "not_applicable", "rejected"])
        stats = await triage_module.fetch_signature_stats(conn, sig_dead)
        ctx = gate._format_gate_outcome_context(stats)
        assert ctx != "", "expected outcome_context for a clean 4/4 rejected/not_applicable history"
        assert "4 time(s)" in ctx and "zero accepted or informative" in ctx
        assert "severity" not in ctx.split("not a severity judgment")[0].lower() or "not a severity judgment" in ctx
        print("PASS (4/4): clean rejected/not_applicable history (n=4) correctly triggers outcome_context:")
        print("   ", ctx.strip())

        print("\nALL PASS")
    finally:
        await conn.execute(
            "DELETE FROM finding_outcomes WHERE signature LIKE 'test-tool:%'"
        )
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
