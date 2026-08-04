-- SWAS Triage Batch Update
-- Source: 7 triage reports (WP Engine, Watsons, Superdrug, Salto, Marionnaud, Toyota, Wolt)
-- Generated 2026-08-03
--
-- IMPORTANT: Verify these against your actual findings table schema before running.
-- Assumed columns: id, status, triage_reason, triaged_at
-- Adjust column names / table name if different (check with: \d findings)

BEGIN;

CREATE TEMP TABLE _triage_batch (
    finding_id  INTEGER PRIMARY KEY,
    new_status  TEXT NOT NULL,
    reason      TEXT NOT NULL
);

INSERT INTO _triage_batch (finding_id, new_status, reason) VALUES
-- ===== WP ENGINE (batch 68) =====
(22717,'false_positive','GraphQL endpoint 404, no such route'),
(22711,'false_positive','CVE unconfirmed, OOS version disclosure'),
(22730,'false_positive','Hidden login URL, no impact'),
(22729,'out_of_scope','Program OOS: WP username disclosure'),
(22731,'out_of_scope','Program OOS: WP username disclosure'),
(22734,'out_of_scope','Program OOS: WP username disclosure'),
(22713,'out_of_scope','Program OOS: WP username disclosure'),
(22712,'out_of_scope','Program OOS: WP username disclosure'),
(22718,'out_of_scope','Program OOS: WP username disclosure'),
(22723,'out_of_scope','Program OOS: WP username disclosure'),
(22737,'out_of_scope','*.getflywheel.com OOS since 2025-09-23'),
(22724,'false_positive','SQLmap: WAF blocked, no injectable params'),
(22725,'false_positive','SQLmap: WAF blocked, no injectable params'),
(22719,'false_positive','SQLmap: WAF blocked, no injectable params'),
(22716,'false_positive','SQLmap: WAF blocked, no injectable params'),
(22715,'false_positive','SQLmap: WAF blocked, no injectable params'),
(22714,'false_positive','SQLmap: WAF blocked, no injectable params'),
(22736,'false_positive','SQLmap: WAF blocked, no injectable params'),
(22732,'false_positive','SQLmap: WAF blocked, no injectable params'),
(22728,'false_positive','SQLmap: WAF blocked, no injectable params'),
(22722,'false_positive','logic_hunter: self-refuted/inconclusive'),
(22735,'false_positive','logic_hunter: self-refuted/inconclusive'),
(22733,'false_positive','logic_hunter: self-refuted/inconclusive'),
(22727,'false_positive','logic_hunter: self-refuted/inconclusive'),
(22726,'false_positive','logic_hunter: self-refuted/inconclusive'),
(22721,'false_positive','logic_hunter: self-refuted/inconclusive'),
(22720,'false_positive','logic_hunter: self-refuted/inconclusive'),

-- ===== WATSONS / AS WATSON (batch 67) =====
(22677,'closed_abandoned','CORS drogas.lt: Intigriti flagged non-sensitive, impact unproven'),
(22674,'closed_abandoned','CORS drogas.lt: Intigriti flagged non-sensitive, impact unproven'),
(22697,'closed_abandoned','CORS drogas.lv: same as above'),
(22563,'out_of_scope','API key is product serial, not cloud key; OOS no proven impact'),
(22464,'false_positive','Google Maps key REQUEST_DENIED, referrer restricted'),
(22462,'false_positive','Google Maps key REQUEST_DENIED, referrer restricted'),
(22436,'false_positive','Origin IP: all probes 403, not exploitable'),
(22435,'false_positive','Origin IP: all probes 403, not exploitable'),
(22429,'out_of_scope','Host header injection OOS without proven impact'),
(22442,'out_of_scope','Host header injection OOS without proven impact'),
(22466,'out_of_scope','Host header injection OOS without proven impact'),
(22258,'out_of_scope','Host header injection OOS without proven impact'),

-- ===== SUPERDRUG (CSV 61) =====
(22328,'false_positive','CRLF: Cloudflare re-encoded, no injected header'),
(22337,'false_positive','Google API key expired/rotated, unverifiable'),
(22350,'out_of_scope','Origin IP is Azure shared infra, not Superdrug origin'),
(22347,'false_positive','SQLmap: 404 at root, no injection attempted'),

-- ===== SALTO HOME SOLUTIONS / DANALOCK (CSV 58) =====
(22279,'out_of_scope','CORS confirmed real but api.danalock.com prod is OOS'),
(22280,'out_of_scope','CORS confirmed real but api.danalock.com prod is OOS'),
(22272,'submitted','CORS arbitrary origin, staging, PII exposed - submitted to Intigriti'),
(22265,'submitted','Duplicate vector, same report as 22272'),
(22273,'submitted','CORS null origin, staging - same report as 22272'),
(22266,'submitted','Duplicate vector, same report as 22272'),
(22274,'false_positive','logic_hunter: self-invalidated'),
(22275,'false_positive','logic_hunter: self-invalidated'),
(22277,'false_positive','logic_hunter: self-invalidated'),
(22278,'false_positive','logic_hunter: self-invalidated'),
(22282,'false_positive','logic_hunter: self-invalidated'),
(22271,'false_positive','SQLmap: connection failed, no payload delivered'),
(22281,'false_positive','SQLmap: connection failed, no payload delivered'),

-- ===== MARIONNAUD (CSV 57) =====
(22202,'false_positive','SSTI: WAF 403 on all requests, no server-side eval'),
(22191,'out_of_scope','CORS suffix bypass: non-sensitive endpoint, attacker origin not reflected'),
(22196,'out_of_scope','CORS suffix bypass: non-sensitive endpoint, attacker origin not reflected'),
(22199,'out_of_scope','CORS suffix bypass: non-sensitive endpoint, attacker origin not reflected'),
(22200,'out_of_scope','CORS suffix bypass: non-sensitive endpoint, attacker origin not reflected'),
(22201,'out_of_scope','CORS suffix bypass: non-sensitive endpoint, attacker origin not reflected'),
(22238,'out_of_scope','CORS suffix bypass: non-sensitive endpoint, attacker origin not reflected'),
(22251,'out_of_scope','CORS suffix bypass: non-sensitive endpoint, attacker origin not reflected'),

-- ===== TOYOTA MOTOR EUROPE (batch 63) =====
(22399,'submitted','Jetty context disclosure + unauth Swagger UI - submitted to Intigriti'),
(22398,'out_of_scope','API key revoked/invalid; OOS no proven impact'),
(22397,'out_of_scope','CORS wildcard+creds unusable per Fetch spec; OOS non-sensitive'),
(22403,'false_positive','logic_hunter: inconclusive, no evidentiary support'),
(22402,'out_of_scope','CORS wildcard+creds unusable per Fetch spec; OOS'),
(22401,'false_positive','SQLmap: 403 on every request, no injectable params'),

-- ===== WOLT (batch 71) =====
(22745,'out_of_scope','Google API key referrer-restricted; OOS no proven impact'),
(22746,'out_of_scope','Google API key referrer-restricted; OOS no proven impact'),
(22740,'false_positive','MCP endpoint 405/404, not accessible via GET'),
(22741,'false_positive','MCP endpoint 405/404, not accessible via GET'),
(22747,'false_positive','SendGrid string is config flag, not a credential'),
(22748,'false_positive','Looker login requires auth, no bypass found'),
(22738,'false_positive','SQLmap target 404, does not exist'),
(22739,'false_positive','SQLmap: no injectable params found'),
(22742,'false_positive','SQLmap: WAF 403 blocked all probes'),
(22743,'false_positive','SQLmap: no injectable params found'),
(22744,'false_positive','SQLmap: WAF 403 blocked, duplicate run')
;

-- Superdrug/Marionnaud CORS bulk ranges (22283-22309, no per-ID reasons in source doc)
INSERT INTO _triage_batch (finding_id, new_status, reason)
SELECT gs, 'out_of_scope', 'CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'
FROM generate_series(22283, 22309) gs
ON CONFLICT (finding_id) DO NOTHING;

UPDATE findings f
SET status = t.new_status,
    triage_reason = t.reason,
    triaged_at = now()
FROM _triage_batch t
WHERE f.id = t.finding_id;

-- Sanity check before commit
SELECT status, count(*) FROM _triage_batch GROUP BY status ORDER BY 1;

COMMIT;
