# SWAS - Security Workflow Automation System

SWAS is a self-hosted platform that automates the repetitive parts of bug
bounty hunting: recon, scanning, verification, and triage. You point it at
a program's in-scope targets, it runs a multi-phase pipeline against them,
and it hands you back a reviewed, deduplicated list of candidate findings
with AI-assisted triage reasoning instead of a raw firehose of scanner
noise.

It is built to run unattended on a small cloud box (the reference deploy
target is an ARM64 Oracle Cloud "Ampere A1" instance) and to be operated
from a browser UI, not the command line.

> **Status:** actively developed, batch by batch. This is a personal
> research tool, not a polished product - expect rough edges.

---

## What it actually does

At a high level, SWAS runs each in-scope target through a pipeline of
phases:

1. **Recon** - subdomain enumeration (`subfinder`), with a time-boxed
   cache so repeated/scheduled scans don't redo the same recon work every
   run.
2. **Probe** - liveness and tech-detection pass (`httpx`) over everything
   recon found.
3. **Fuzz** - hidden parameter discovery (`arjun`) on live endpoints.
4. **Scan** - the biggest phase. Runs `nuclei` template scans plus a large
   internal library of "detective" checks (see below) against every live
   host, URL, and discovered parameter.
5. **Verify** - impact-proof probes that try to actually demonstrate real
   impact for candidate findings (e.g. confirming SQLi with a real
   response-based check, path traversal by reading a known file, JWT
   forgery/replay, cloud storage misconfig, GraphQL over-fetching) rather
   than just flagging a signature match.
6. **Gate** - a policy/outcome-aware gate that can hold back or downgrade
   findings that historically get rejected for a given signature, or that
   fall outside a program's documented scope/exclusions.
7. **Logic Hunter / Triage** - an AI-assisted pass (Gemini, with optional
   fallback providers) that reasons about each finding, writes a
   human-readable explanation, and flags likely duplicates or
   false-positive patterns.
8. **Report** - turns triaged findings into a structured, exportable
   report draft.

Everything above is orchestrated by a background pipeline
(`pipeline/orchestrator.py`), with per-phase state persisted to Postgres
so a crash or restart mid-scan doesn't silently lose progress - interrupted
runs are detected and flagged on startup.

### The "detective" check library

Rather than relying only on `nuclei` templates, SWAS has a hand-written,
pure-Python detector library (`backend/app/detective/`), organized by
category:

| Module | Covers |
|---|---|
| `injection.py` | SQLi, SSTI, XXE, LDAP/XPath injection, command injection, prototype pollution, NoSQL injection, LFI/path traversal, insecure deserialization, CRLF/host-header/param-pollution bugs |
| `auth_access.py` | JWT abuse, CORS, CSRF, IDOR, HTTP verb tampering/method override, mass assignment, session/cookie handling, rate limiting, OAuth state, admin panel access, API key exposure |
| `client_side.py` | Reflected/DOM XSS, JSONP callback XSS, clickjacking, insecure file/SVG upload |
| `ssrf.py` | Reflected/blind SSRF, cloud metadata credential theft (AWS/GCP/Azure/DigitalOcean), internal port scanning via SSRF |
| `cloud_storage.py` | Exposed S3/Azure buckets, Firebase misconfiguration |
| `infra_exposure.py` | Leaked git/docker/k8s/CI config, debug endpoints, exposed DB/dev-tool admin consoles, backup/dump files, missing security headers |
| `recon_misc.py` | Subdomain takeover, cache deception/poisoning, WAF fingerprinting, GraphQL introspection, open redirect variants |

An **agentic investigation loop** (`agent_loop.py`) can also take a
candidate finding and run a bounded, multi-step follow-up investigation
(hard-capped steps, with a forced-conclude fallback) instead of stopping
at a single request/response check.

### Authenticated / multi-account testing

SWAS supports logged-in scanning against real programs, gated by policy:

- `auth_policy.py` - default-deny per-program policy: a program has to be
  explicitly allowed before authenticated testing runs against it.
- `auth_sessions.py` - session material (cookies/tokens) is stored
  encrypted at rest via `pgcrypto`, not in plaintext.
- `auth_cli.py` - a standalone CLI for registering credentials that uses
  `getpass`, so secrets never land in shell history.

### Policy-awareness and false-positive reduction

A recurring design goal in this tool is to avoid wasting your time on
findings that are technically real but will get closed as
Informative/Not Applicable:

- `policy_gate.py` / `gate.py` - can hold back low-value classes and
  factors in a signature's historical outcome record (repeated
  rejections for the same finding type get down-weighted).
- `fp_filter.py` - filters known noisy categories by default: SSL/TLS
  and certificate findings and missing-security-header noise are always
  filtered, since mature programs consistently close these as
  Informational. Open redirects, subdomain takeover without proof, and
  DNS SPF/DMARC gaps are filtered under an optional strict mode you can
  toggle per deploy (`FP_FILTER_STRICT_MODE`).
- `NUCLEI_EXCLUDE_TAGS` / `NUCLEI_MIN_SEVERITY` - configurable at the
  scanner level, defaulting to skipping `ssl,tls` tags and `info`-severity
  results, since real scan data showed the large majority of raw
  `info`-tier nuclei output was recon noise, not reportable findings.
- `DENYLIST_DOMAINS` - a hard, defense-in-depth denylist so a domain a
  program explicitly excludes can never be scanned even if it's
  accidentally marked in-scope.

### Dashboard / UI

A React frontend (`frontend/`) provides:

- Project list and per-project detail views, with a scope manager and
  scope-intake flow for pasting in a program's target list
- A findings list, triage queue, and diff panel for reviewing candidate
  findings
- A live pipeline tracker over WebSocket, so you can watch a scan
  progress phase by phase in real time
- An execution queue and scheduled-scans page for running scans on a
  recurring cadence
- An observability page and signature-stats view for tracking outcome
  history (accept/reject rates) per finding signature
- A command palette and keyboard shortcuts for fast navigation

---

## Architecture

```
                        ┌────────────────────┐
   Browser  ───HTTPS──▶ │   Caddy (reverse    │
  (basic auth)          │   proxy + TLS +     │
                        │   basic_auth gate)  │
                        └─────────┬───────────┘
                     ┌────────────┼─────────────┐
                     ▼                          ▼
            ┌────────────────┐        ┌──────────────────┐
            │ frontend (Vite/ │        │ backend (FastAPI) │
            │ React, static)  │        │  /api/*  /ws/*     │
            └────────────────┘        └─────────┬─────────┘
                                                  │
                                  ┌───────────────┼───────────────┐
                                  ▼               ▼               ▼
                           ┌───────────┐   ┌────────────┐  ┌────────────┐
                           │ Postgres  │   │   Redis    │  │  Scanning  │
                           │ (findings,│   │ (queue/    │  │  tools:    │
                           │ projects, │   │  caching)  │  │ subfinder, │
                           │ scope,    │   └────────────┘  │ httpx,     │
                           │ outcomes) │                   │ nuclei,    │
                           └───────────┘                   │ sqlmap,    │
                                                            │ dalfox,    │
                                                            │ arjun, ... │
                                                            └────────────┘
```

Everything runs as Docker Compose services: `postgres`, `redis`,
`backend`, `frontend`, and `caddy`, all on an internal bridge network with
only Caddy's ports 80/443 exposed to the outside.

The backend FastAPI app is organized as:

- `routers/` - one `APIRouter` per area (`projects`, `scope`, `findings`,
  `scanning`, `reports`, `health`, `live`), wired together in `main.py`
- `pipeline/` - the phase orchestrator (`orchestrator.py`) plus one module
  per phase (`phase_recon.py`, `phase_probe.py`, `phase_fuzz.py`,
  `phase_scan.py`, `phase_post.py` for verify/gate/logic_hunter/triage/
  notify)
- `detective/` - the pure-Python vulnerability check library described
  above
- `scan_orchestration.py` - the background loops: scheduler, scan-queue
  worker, daily digest, stale-project flagging, AI retry queue
- `gemini_rotation.py` - rotates across multiple Gemini API keys and, once
  every key/model combination is exhausted for the day, falls through to
  optional tier-2 providers (DeepSeek, GLM, or a list of Llama models via
  OpenRouter or NVIDIA), with a per-model circuit breaker so a broken
  model doesn't get retried indefinitely

---

## Scanning tools used

Installed automatically in the backend Docker image (multi-stage build -
Go tools are compiled in a builder stage, Go itself is not shipped in the
final image):

| Tool | Purpose |
|---|---|
| `subfinder` | Subdomain enumeration |
| `httpx` (renamed `httpx-pd` in-image to avoid a naming collision with the Python `httpx` library's own CLI) | Liveness/tech-detection probing |
| `nuclei` | Template-based vulnerability scanning |
| `notify` | Notification delivery |
| `gau` / `waybackurls` | Historical URL discovery |
| `ffuf` | Fuzzing |
| `dalfox` | XSS scanning |
| `interactsh-client` | Out-of-band interaction confirmation (blind SSRF, etc.), via the public `oast.*` servers by default |
| `sqlmap` | SQL injection testing (git-cloned and wrapped, since it ships as a script, not a package) |
| `arjun` | Hidden parameter discovery |

Playwright (for headless-browser XSS execution proof) is **not** installed
by default to keep the image size and ARM64 build time down. `verify.py`
already handles its absence gracefully by skipping that one technique.
It's a documented opt-in - see the comment block in `backend/Dockerfile`
for the three-line change to enable it.

---

## Getting started

### Prerequisites

- A server with Docker and Docker Compose installed (reference target:
  ARM64 Oracle Cloud "Ampere A1" instance, but any Docker host works)
- A Google AI Studio API key for Gemini (required - this is what powers
  triage/scope-parsing)

### 1. Clone and configure

```bash
git clone https://github.com/yr369/swas-tool-g1.git
cd swas-tool-g1
cp .env.example .env
```

Edit `.env` and fill in, at minimum:

- `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB`
- `GEMINI_API_KEY` (extra `GEMINI_API_KEY_2`, `_3`, ... are optional -
  each Google AI Studio key has its own independent free-tier quota, so
  more keys means more headroom before falling back to tier-2 providers)

Everything else in `.env.example` is documented inline and optional
(tier-2 AI fallback providers, notification webhook, researcher
identification header for programs that require one, hard scope
denylist, nuclei tag/severity filtering, recon cache TTL, FP-filter
strict mode, allowed CORS origins).

### 2. Set up the auth gate

The whole app - UI, API, and WebSocket - sits behind HTTP basic auth via
Caddy, so an exposed server IP alone doesn't give anyone access.

```bash
docker compose up -d          # first run, so the caddy image exists locally
docker compose exec caddy caddy hash-password --plaintext 'yourpassword'
```

Paste the resulting bcrypt hash into `SWAS_AUTH_HASH` in `.env`, pick any
username for `SWAS_AUTH_USER`, then:

```bash
docker compose restart caddy
```

Leaving `SWAS_AUTH_USER`/`SWAS_AUTH_HASH` blank is intentional-by-design a
hard failure - Caddy will refuse to start rather than run with no real
password.

### 3. Bring everything up

```bash
docker compose up -d --build
docker compose ps        # confirm every service is "running" or "healthy"
```

The UI is served on port 80/443 through Caddy. Point a domain at the
server and switch the Caddyfile's `:80` to your domain name to get
automatic HTTPS - no other config needed for that part.

### 4. Deploying updates later

```bash
./deploy.sh
```

This pulls the latest code, rebuilds any changed images, restarts
services, and prints status. Run it **on the server**, not your local
machine.

---

## Configuration reference

All runtime configuration lives in `.env` (see `.env.example` for the
full, commented list). The notable per-deploy toggles:

- `RESEARCH_HEADER_NAME` / `RESEARCH_HEADER_VALUE` - many programs want
  an identifying header on all scan traffic so their security team can
  tell authorized researcher activity apart from a real attack (e.g.
  Bugcrowd's `X-Bug-Bounty` header). Leave blank for targets that don't
  require one.
- `DENYLIST_DOMAINS` - comma-separated domain fragments that must never
  be scanned, defense-in-depth against a target being marked in-scope by
  mistake.
- `NUCLEI_EXCLUDE_TAGS` / `NUCLEI_MIN_SEVERITY` - trim scan noise and scan
  time; both default to sensible values but can be relaxed per program.
- `RECON_CACHE_HOURS` - how long a subdomain enumeration result stays
  reusable before recon re-runs for real; set to `0` to always run fresh.
- `FP_FILTER_STRICT_MODE` - opt-in extra filtering for open redirects,
  unproven subdomain takeovers, and DNS SPF/DMARC gaps. Check a given
  program's brief before enabling, since some programs do want these
  reported.

---

## Project layout

```
backend/
  app/
    routers/        FastAPI route handlers, one file per area
    pipeline/        Phase orchestrator + one module per pipeline phase
    detective/       Pure-Python vulnerability check library
    tests/           Manual/integration-style test scripts (no mocking -
                      real DB, real HTTP server, real API error classes)
    main.py          App entry point: startup/shutdown, CORS, router wiring
    tools.py         Subprocess wrapper for CLI scanning tools
    verify.py        Impact-proof probes for candidate findings
    gate.py / policy_gate.py   Policy- and outcome-aware finding gating
    agent_loop.py    Bounded agentic follow-up investigation
    auth_policy.py / auth_sessions.py / auth_cli.py   Authenticated scanning
    gemini_rotation.py   Multi-key/multi-provider AI call rotation
    scan_orchestration.py   Background loops (scheduler, queue, digest, retry)
  db/                SQL migrations and queries
  Dockerfile
frontend/
  src/
    pages/           Top-level views (Dashboard, ProjectDetail, TriageQueue, ...)
    components/       Reusable UI pieces (FindingsList, PipelineTracker, ...)
    api/              Backend API client
docker/caddy/         Caddyfile (reverse proxy + basic auth)
scripts/              Operational helper scripts (PowerShell diagnostics, etc.)
docker-compose.yml
.env.example
deploy.sh
```

---

## Notes and caveats

- This is a **personal, self-hosted research tool** aimed at automating a
  single operator's own authorized testing workflow - it is not designed
  for multi-tenant or public-facing use.
- Authenticated scanning is default-deny per program on purpose. Review
  `auth_policy.py` before pointing it at a program that requires
  session-based testing.
- False-positive filtering defaults are opinionated (based on real
  observed outcome data), but every program's policy is different -
  review `FP_FILTER_STRICT_MODE`, `NUCLEI_EXCLUDE_TAGS`, and
  `DENYLIST_DOMAINS` against the specific program's brief before running
  a scan, and always confirm a category isn't excluded by that program's
  policy before submitting anything the tool surfaces.
- Verify your own scope and rules of engagement independently; nothing
  here substitutes for reading a program's actual policy page.

---

## License

No license file is currently included in this repository - treat it as
all-rights-reserved by the author unless/until one is added.
