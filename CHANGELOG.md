# Changelog

All notable changes to SWAS Tool are logged here from now on, replacing
the old pattern of individual `.patch` files in the repo root.

## [Unreleased] - Upgrade in progress

### Batch 1 - Repo Cleanup
- Removed 39 stale `.patch` files from repo root (history preserved in git log)
- Removed `_backup_20260716_113102/` dated backup folder
- Added this CHANGELOG.md

### Planned
- Batch 2: JWT testing module (jwt_tool)
- Batch 3: Secret/leak scanning (Gitleaks) + exposed `.git` detection
- Batch 4: NoSQL injection scanning (NoSQLMap)
- Batch 5: Policy-gate outcome surfacing in UI (backend already exists in triage.py)
- Batch 6: Ops UI - per-host rescan, queue system, scheduled scans, typed-delete confirm
- Batch 7: Homepage redesign - command palette + attack surface map

---
_Existing functionality (subfinder/httpx/gau/Arjun recon layer, Nuclei,
sqlmap/Dalfox/Autorize/SSRFmap/XXEinjector/tplmap/ysoserial/Commix/
GraphQLmap detective batches, AI-driven triage with policy-exclusion
reasoning) was already implemented prior to this changelog and is not
re-listed here._
