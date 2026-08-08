"""
pipeline/shared.py - module-level constants shared across the pipeline
package: per-check request caps (moved here rather than duplicated in
phase_scan.py so a new cap constant has one obvious home), the
package logger (kept as "swas.pipeline" - unchanged - so existing log
filters/greps on that name keep working), and the phase-name list.
"""

import logging
import os

_TAKEOVER_CHECK_CAP = 15
_SENSITIVE_URL_CHECK_CAP = 15
_SQLI_TIMING_CHECK_CAP = 8      # each test costs a deliberate multi-second delay - keep tight
_SOURCE_MAP_CHECK_CAP = 10
_OPEN_REDIRECT_CHECK_CAP = 15
_CRLF_CHECK_CAP = 15
_HPP_CHECK_CAP = 15
_SSRF_CHECK_CAP = 15
_SSTI_CHECK_CAP = 10           # multiple payloads tried per param - keep tighter
_IDOR_CANDIDATE_CHECK_CAP = 40 # pure regex match, no network request - cheap
_XSS_CHECK_CAP = 15
_SQLI_ERROR_CHECK_CAP = 10     # extra baseline request per URL on top of per-param probes
_XXE_CHECK_CAP = 10
_DESERIALIZATION_CHECK_CAP = 20
_PATH_TRAVERSAL_CHECK_CAP = 15
_CMDI_CHECK_CAP = 8            # each real hit costs a deliberate multi-second delay - keep tight
_BUCKET_EXPOSURE_CHECK_CAP = 15
_METHOD_OVERRIDE_CHECK_CAP = 15
_REFERRER_LEAK_CHECK_CAP = 15
_OPEN_REDIRECT_ENCODING_CHECK_CAP = 15
_SRI_CHECK_CAP = 15
_SSRF_PORT_SCAN_CHECK_CAP = 15
_MASS_ASSIGNMENT_CHECK_CAP = 15
_VERB_TAMPERING_CHECK_CAP = 15
_NEGATIVE_NUMBER_CHECK_CAP = 15
_PREDICTABLE_TOKEN_CHECK_CAP = 25  # pure pattern match, no extra requests beyond the URL's own
_CLICKJACKING_CHECK_CAP = 15
_HARDCODED_SECRETS_CHECK_CAP = 15
_LFI_PHP_WRAPPER_CHECK_CAP = 10
_LDAP_INJECTION_CHECK_CAP = 10
_XPATH_INJECTION_CHECK_CAP = 10
_CACHE_POISONING_CHECK_CAP = 15
_CSRF_TOKEN_CHECK_CAP = 15
_FILE_UPLOAD_CANDIDATE_CHECK_CAP = 15
_WEBSOCKET_DOWNGRADE_CHECK_CAP = 15
_EXCESSIVE_EXPOSURE_CHECK_CAP = 15
_API_VERSION_DOWNGRADE_CHECK_CAP = 15
_SQLI_BOOLEAN_CHECK_CAP = 10
_SVG_UPLOAD_CHECK_CAP = 15
_JSONP_XSS_CHECK_CAP = 15
_BACKUP_FILE_CHECK_CAP = 15
_AZURE_BLOB_CHECK_CAP = 15
_CORS_SUBDOMAIN_BYPASS_CHECK_CAP = 15
_HSTS_CHECK_CAP = 15
_COOKIE_SAMESITE_CHECK_CAP = 15
_SESSION_ID_URL_CHECK_CAP = 25  # pure pattern match, no extra requests
_META_REFRESH_CHECK_CAP = 15
_WSDL_CHECK_CAP = 15
_UUID_VERSION_CHECK_CAP = 25  # pure pattern match, no extra requests
_OAUTH_STATE_CHECK_CAP = 15
_BASIC_AUTH_HTTP_CHECK_CAP = 15
_COOKIE_SECURE_CHECK_CAP = 15
_FIREBASE_RTDB_CHECK_CAP = 15
_SSRF_GCP_CHECK_CAP = 10
_SSRF_AZURE_CHECK_CAP = 10
_SSRF_DO_CHECK_CAP = 10
_XFF_BYPASS_CHECK_CAP = 15
_REFERER_BYPASS_CHECK_CAP = 15
_APIKEY_IN_URL_CHECK_CAP = 25  # pure pattern match, no extra requests
_PW_RESET_ENUM_CHECK_CAP = 10
# Batch 22 - data/access impact probes. Each does at least one extra
# live request beyond its candidate-only predecessor, so capped at the
# same conservative level as the other request-issuing checks above.
# (The 3 host-level probes - GraphQL field exposure, admin functional
# access, JWT forgery - don't need their own cap constant, same as
# every other host-level check: they run once per host inside the
# already-capped live_hosts[:10] loop, not their own candidate list.)
_IDOR_IMPACT_CHECK_CAP = 15
_SQLI_UNION_CHECK_CAP = 10
_LFI_CONFIRM_CHECK_CAP = 10
_BUCKET_OBJECT_EXTRACT_CHECK_CAP = 15

# Batch 23 - behavioral/chain impact probes. Multi-step (SSRF credential
# chase, headless-browser cookie exfil, OAuth redirect chain, CSRF
# preflight, rate-limit burst) so capped tighter than batch 22's single-
# extra-request probes. (Dangling NS delegation takeover is host-level,
# runs once per host inside the already-capped subdomain-takeover loop -
# no separate cap constant needed, same convention as other host-level
# checks.)
_SSRF_METADATA_CRED_CHECK_CAP = 8
_XSS_COOKIE_EXFIL_CHECK_CAP = 6       # real headless browser launch per candidate - expensive
_OAUTH_REDIRECT_CHAIN_CHECK_CAP = 10
_CSRF_POC_CHECK_CAP = 10
_RATE_LIMIT_BYPASS_CHECK_CAP = 6      # deliberately bursts up to 12 requests per candidate

logger = logging.getLogger("swas.pipeline")

PHASES = ["recon", "probe", "fuzz", "scan", "verify", "gate", "logic_hunter", "triage", "notify"]

# Wall-clock cap per phase, per target. Every individual HTTP call inside
# detective/*.py already has its own httpx timeout, and subprocess calls
# (oob.py, tools.py) are already wrapped in asyncio.wait_for - but nothing
# capped the PHASE as a whole. A phase stuck in a retry/polling loop that
# never itself raises (a hung tool subprocess not covered by tools.py's
# wrapper, a pathological target, a stuck websocket read, etc.) could run
# indefinitely - this is the confirmed cause of scans sitting in
# 'scanning' for hours with nothing actually happening. scan gets the
# longest budget (it runs ~130 detective.py checks across every live
# host); notify is a single webhook POST and gets the shortest. Override
# per-phase with PHASE_TIMEOUT_<PHASE>_SECONDS (e.g.
# PHASE_TIMEOUT_SCAN_SECONDS=7200) without touching code.
_DEFAULT_PHASE_TIMEOUT_SECONDS = int(os.environ.get("PHASE_TIMEOUT_DEFAULT_SECONDS", str(30 * 60)))

PHASE_TIMEOUT_SECONDS = {
    "recon": int(os.environ.get("PHASE_TIMEOUT_RECON_SECONDS", str(20 * 60))),
    "probe": int(os.environ.get("PHASE_TIMEOUT_PROBE_SECONDS", str(15 * 60))),
    "fuzz": int(os.environ.get("PHASE_TIMEOUT_FUZZ_SECONDS", str(30 * 60))),
    "scan": int(os.environ.get("PHASE_TIMEOUT_SCAN_SECONDS", str(90 * 60))),
    "verify": int(os.environ.get("PHASE_TIMEOUT_VERIFY_SECONDS", str(30 * 60))),
    "gate": int(os.environ.get("PHASE_TIMEOUT_GATE_SECONDS", str(20 * 60))),
    "logic_hunter": int(os.environ.get("PHASE_TIMEOUT_LOGIC_HUNTER_SECONDS", str(20 * 60))),
    "triage": int(os.environ.get("PHASE_TIMEOUT_TRIAGE_SECONDS", str(30 * 60))),
    "notify": int(os.environ.get("PHASE_TIMEOUT_NOTIFY_SECONDS", str(2 * 60))),
}


def timeout_for_phase(phase_name: str) -> int:
    return PHASE_TIMEOUT_SECONDS.get(phase_name, _DEFAULT_PHASE_TIMEOUT_SECONDS)


