# scripts/

Standalone PowerShell helpers for local diagnostics against the OCI
deployment. Not part of the app itself - nothing in `backend/` or
`frontend/` imports these.

- `secret_verification.ps1` - verifies leaked-secret findings against
  live endpoints before they go in a report.
- `rescan_diagnostics.ps1` - diagnoses/retriggers a stuck or failed
  rescan for a single target.
- `diagnose.ps1` - general project/pipeline state diagnostics.

`archive/` holds one-off patch/fix scripts that have already been
applied to the running deployment. Kept for history, not meant to be
re-run - each is suffixed `.applied`.

Database migrations live in `backend/db/migrations/`, numbered and
replayed in order - see that folder's existing files for the pattern.
Loose one-off `.sql` files that used to sit at repo root (batch25_26,
evidence_lifecycle, phase_runs constraint fix) were folded into that
numbered sequence as 014-016 during the Aug 2026 repo compaction pass.
