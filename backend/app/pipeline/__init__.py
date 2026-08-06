"""
pipeline package __init__.py - explicit re-exports only (no wildcard
imports), same convention as detective/__init__.py after the bug
where a wildcard import silently dropped underscore-prefixed names
and caused a production 502. The only name anything outside this
package actually uses is run_target_pipeline (confirmed by grep
before this split - main.py is the sole external caller), but the
rest are re-exported too so `pipeline._phase_scan` etc. keeps working
for anyone poking at internals from a shell/debugger the way it did
when this was one file.
"""

from .orchestrator import run_target_pipeline, _run_phase_with_retry, _execute_phase
from .phase_recon import _phase_recon
from .phase_probe import _phase_probe
from .phase_fuzz import _phase_fuzz
from .phase_scan import _phase_scan
from .phase_post import _phase_verify, _phase_gate, _phase_logic_hunter, _phase_triage, _phase_notify
from .persistence import (
    _log_aem_pivot_hint, _save_finding_pooled, _save_nuclei_findings_pooled,
    _save_scan_note_pooled, _get_recon_cache_if_fresh, _save_recon_cache_pooled,
    _persist_pipeline_state, _infer_requires_auth, _save_surface_endpoints_pooled,
    _parse_arjun_params, _save_surface_params_pooled, _save_detective_finding_pooled,
    _save_nuclei_findings, _upsert_finding_cluster, _save_finding, _save_scan_note,
    _save_detective_finding,
)
from .shared import logger, PHASES
