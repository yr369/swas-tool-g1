-- SWAS finding_outcomes insert - bug bounty submits log book
-- Source: Bug-Bounty-submits-log-book.xlsx (BugCrowd, HackerOne, Intigriti, YesWeHack)
-- Generated 2026-08-03
--
-- SKIPPED (no resolved outcome yet, still Open/New):
--   - HackerOne #3889937 FloQast host header injection (New/Open)
--   - Intigriti SALTOSYSTEMS-AOQKU041 Salto/Danalock CORS (Open) - matches SWAS findings
--     22272/22265/22273/22266, already marked submitted/accepted in prior batch. Re-run this
--     script's pattern once it closes to log the final outcome.
--
-- finding_id is NULL on every row here - none could be confidently matched to a specific
-- SWAS findings.id. Match later via `signature` once your outcome-learning loop is wired up,
-- or update finding_id manually if you can confirm the mapping.

BEGIN;

INSERT INTO finding_outcomes (finding_id, signature, outcome, platform, notes) VALUES
(NULL, 'unauthenticated_cache_purge:mca.scoober.com', 'not_applicable', 'bugcrowd', 'BugCrowd report 7dcd9904-312c-4f68-8ade-7f91d0ba4e2d, Just Eat Takeaway.com. Reward 0. Closing reason: unauthenticated Varnish cache purge on CDN has negligible impact; would need network-level DoS to matter, which is OOS.'),
(NULL, 'dns_subdomain_takeover:je-il-rc-staging.just-eat.co.il', 'rejected', 'bugcrowd', 'BugCrowd report d0de6540-017c-4b40-947d-711d9ba99c72, Just Eat Takeaway.com. Reward -1 (invalid penalty). Closing reason: not reproducible - report only showed theoretical takeover, no actual claimed Azure service / PoC file served.'),
(NULL, 'unauthenticated_cache_purge:my.royalcanin.sk', 'informative', 'hackerone', 'HackerOne #3848817, Mars. Reward 0.0. Closing reason: DoS/Resource Exhaustion explicitly excluded from scope; no measurable disruption beyond cache state change.'),
(NULL, 'cors_subdomain_suffix_bypass:www.agoda.com', 'not_applicable', 'hackerone', 'HackerOne #3865202, Agoda Public. Reward -5.0 (invalid penalty). Closing reason: no CIA-triad impact per analyst, unanchored suffix CORS bypass on agoda.com.'),
(NULL, 'cors_arbitrary_origin_credentials:login.rei.com', 'duplicate', 'hackerone', 'HackerOne #3883254, REI BBP. Reward 0.0. Duplicate of #3670307 ("Critical CORS Misconfiguration Leading to Account Takeover on login.rei.com", submitted Apr 13 2026). Matches prior SWAS/REI triage finding of the same CORS pattern (no specific finding_id available from that report).'),
(NULL, 'exposed_nexus_repository:furycloud.io', 'duplicate', 'hackerone', 'HackerOne #3889577, MercadoLibre. Reward 0.0. Duplicate of #1466891 (submitted Feb 1 2022). Unauthenticated Nexus repo exposing iOS/Android SDK source, including MercadoPago SecureInputs.'),
(NULL, 'exposed_api_key:es.shein.com', 'duplicate', 'hackerone', 'HackerOne #3897973, SHEIN. Reward 0.0. Duplicate of #2805242 (submitted Oct 26 2024). Live unrestricted Google Cloud API key on es.shein.com, confirmed exploitation via Places/Static Maps APIs.'),
(NULL, 'cors_subdomain_suffix_bypass:en.kolikkopelit.com', 'informative', NULL, 'Platform: YesWeHack. Report #YWH-PGM12166-640, FDJ United. Reward -4 (invalid penalty). Status RTFS - "no practical impact found". Unanchored substring Origin check on /robots.txt (static resource, credentials allowed). NOTE: likely corresponds to one of SWAS findings 22191/22196/22199/22200/22201/22238/22251 (Marionnaud CORS bulk batch, kolikkopelit.com target) but the source triage report did not map specific IDs to specific targets within that group - finding_id left NULL, confirm manually if you want it linked.'),
(NULL, 'open_redirect_host_header:www.unibet.com', 'informative', NULL, 'Platform: YesWeHack. Report #YWH-PGM12166-641, FDJ United. Reward -4 (invalid penalty). Status RTFS - "no security risk or impact". Unvalidated Host header trusted for redirect on www.unibet.com root path.');

SELECT platform, outcome, count(*) FROM finding_outcomes
WHERE recorded_at > now() - interval '5 minutes'
GROUP BY platform, outcome ORDER BY 1,2;

COMMIT;
