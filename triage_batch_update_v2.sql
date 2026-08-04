-- SWAS Triage Batch Update (v2 - matches real findings schema)
-- Source: 7 triage reports (WP Engine, Watsons, Superdrug, Salto, Marionnaud, Toyota, Wolt)
-- Generated 2026-08-03
--
-- Maps to real columns: status (new/reviewed/submitted/dismissed),
-- likely_program_outcome (accepted/informative/out_of_scope/duplicate),
-- triage_reasoning (free text)

BEGIN;

CREATE TEMP TABLE _triage_batch (
    finding_id  INTEGER PRIMARY KEY,
    new_status  TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    reason      TEXT NOT NULL
);

INSERT INTO _triage_batch (finding_id, new_status, outcome, reason) VALUES
(22717,'dismissed','informative','GraphQL endpoint 404, no such route'),
(22711,'dismissed','informative','CVE unconfirmed, OOS version disclosure'),
(22730,'dismissed','informative','Hidden login URL, no impact'),
(22729,'dismissed','out_of_scope','Program OOS: WP username disclosure'),
(22731,'dismissed','out_of_scope','Program OOS: WP username disclosure'),
(22734,'dismissed','out_of_scope','Program OOS: WP username disclosure'),
(22713,'dismissed','out_of_scope','Program OOS: WP username disclosure'),
(22712,'dismissed','out_of_scope','Program OOS: WP username disclosure'),
(22718,'dismissed','out_of_scope','Program OOS: WP username disclosure'),
(22723,'dismissed','out_of_scope','Program OOS: WP username disclosure'),
(22737,'dismissed','out_of_scope','*.getflywheel.com OOS since 2025-09-23'),
(22724,'dismissed','informative','SQLmap: WAF blocked, no injectable params'),
(22725,'dismissed','informative','SQLmap: WAF blocked, no injectable params'),
(22719,'dismissed','informative','SQLmap: WAF blocked, no injectable params'),
(22716,'dismissed','informative','SQLmap: WAF blocked, no injectable params'),
(22715,'dismissed','informative','SQLmap: WAF blocked, no injectable params'),
(22714,'dismissed','informative','SQLmap: WAF blocked, no injectable params'),
(22736,'dismissed','informative','SQLmap: WAF blocked, no injectable params'),
(22732,'dismissed','informative','SQLmap: WAF blocked, no injectable params'),
(22728,'dismissed','informative','SQLmap: WAF blocked, no injectable params'),
(22722,'dismissed','informative','logic_hunter: self-refuted/inconclusive'),
(22735,'dismissed','informative','logic_hunter: self-refuted/inconclusive'),
(22733,'dismissed','informative','logic_hunter: self-refuted/inconclusive'),
(22727,'dismissed','informative','logic_hunter: self-refuted/inconclusive'),
(22726,'dismissed','informative','logic_hunter: self-refuted/inconclusive'),
(22721,'dismissed','informative','logic_hunter: self-refuted/inconclusive'),
(22720,'dismissed','informative','logic_hunter: self-refuted/inconclusive'),
(22677,'dismissed','informative','CORS drogas.lt: Intigriti flagged non-sensitive, impact unproven'),
(22674,'dismissed','informative','CORS drogas.lt: Intigriti flagged non-sensitive, impact unproven'),
(22697,'dismissed','informative','CORS drogas.lv: same as above'),
(22563,'dismissed','out_of_scope','API key is product serial, not cloud key; OOS no proven impact'),
(22464,'dismissed','informative','Google Maps key REQUEST_DENIED, referrer restricted'),
(22462,'dismissed','informative','Google Maps key REQUEST_DENIED, referrer restricted'),
(22436,'dismissed','informative','Origin IP: all probes 403, not exploitable'),
(22435,'dismissed','informative','Origin IP: all probes 403, not exploitable'),
(22429,'dismissed','out_of_scope','Host header injection OOS without proven impact'),
(22442,'dismissed','out_of_scope','Host header injection OOS without proven impact'),
(22466,'dismissed','out_of_scope','Host header injection OOS without proven impact'),
(22258,'dismissed','out_of_scope','Host header injection OOS without proven impact'),
(22328,'dismissed','informative','CRLF: Cloudflare re-encoded, no injected header'),
(22337,'dismissed','informative','Google API key expired/rotated, unverifiable'),
(22350,'dismissed','out_of_scope','Origin IP is Azure shared infra, not Superdrug origin'),
(22347,'dismissed','informative','SQLmap: 404 at root, no injection attempted'),
(22279,'dismissed','out_of_scope','CORS confirmed real but api.danalock.com prod is OOS'),
(22280,'dismissed','out_of_scope','CORS confirmed real but api.danalock.com prod is OOS'),
(22272,'submitted','accepted','CORS arbitrary origin, staging, PII exposed - submitted to Intigriti'),
(22265,'submitted','accepted','Duplicate vector, same report as 22272'),
(22273,'submitted','accepted','CORS null origin, staging - same report as 22272'),
(22266,'submitted','accepted','Duplicate vector, same report as 22272'),
(22274,'dismissed','informative','logic_hunter: self-invalidated'),
(22275,'dismissed','informative','logic_hunter: self-invalidated'),
(22277,'dismissed','informative','logic_hunter: self-invalidated'),
(22278,'dismissed','informative','logic_hunter: self-invalidated'),
(22282,'dismissed','informative','logic_hunter: self-invalidated'),
(22271,'dismissed','informative','SQLmap: connection failed, no payload delivered'),
(22281,'dismissed','informative','SQLmap: connection failed, no payload delivered'),
(22202,'dismissed','informative','SSTI: WAF 403 on all requests, no server-side eval'),
(22191,'dismissed','out_of_scope','CORS suffix bypass: non-sensitive endpoint, attacker origin not reflected'),
(22196,'dismissed','out_of_scope','CORS suffix bypass: non-sensitive endpoint, attacker origin not reflected'),
(22199,'dismissed','out_of_scope','CORS suffix bypass: non-sensitive endpoint, attacker origin not reflected'),
(22200,'dismissed','out_of_scope','CORS suffix bypass: non-sensitive endpoint, attacker origin not reflected'),
(22201,'dismissed','out_of_scope','CORS suffix bypass: non-sensitive endpoint, attacker origin not reflected'),
(22238,'dismissed','out_of_scope','CORS suffix bypass: non-sensitive endpoint, attacker origin not reflected'),
(22251,'dismissed','out_of_scope','CORS suffix bypass: non-sensitive endpoint, attacker origin not reflected'),
(22399,'submitted','accepted','Jetty context disclosure + unauth Swagger UI - submitted to Intigriti'),
(22398,'dismissed','out_of_scope','API key revoked/invalid; OOS no proven impact'),
(22397,'dismissed','out_of_scope','CORS wildcard+creds unusable per Fetch spec; OOS non-sensitive'),
(22403,'dismissed','informative','logic_hunter: inconclusive, no evidentiary support'),
(22402,'dismissed','out_of_scope','CORS wildcard+creds unusable per Fetch spec; OOS'),
(22401,'dismissed','informative','SQLmap: 403 on every request, no injectable params'),
(22745,'dismissed','out_of_scope','Google API key referrer-restricted; OOS no proven impact'),
(22746,'dismissed','out_of_scope','Google API key referrer-restricted; OOS no proven impact'),
(22740,'dismissed','informative','MCP endpoint 405/404, not accessible via GET'),
(22741,'dismissed','informative','MCP endpoint 405/404, not accessible via GET'),
(22747,'dismissed','informative','SendGrid string is config flag, not a credential'),
(22748,'dismissed','informative','Looker login requires auth, no bypass found'),
(22738,'dismissed','informative','SQLmap target 404, does not exist'),
(22739,'dismissed','informative','SQLmap: no injectable params found'),
(22742,'dismissed','informative','SQLmap: WAF 403 blocked all probes'),
(22743,'dismissed','informative','SQLmap: no injectable params found'),
(22744,'dismissed','informative','SQLmap: WAF 403 blocked, duplicate run'),
(22283,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22284,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22285,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22286,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22287,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22288,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22289,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22290,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22291,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22292,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22293,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22294,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22295,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22296,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22297,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22298,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22299,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22300,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22301,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22302,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22303,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22304,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22305,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22306,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22307,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22308,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints'),
(22309,'dismissed','out_of_scope','CORS suffix bypass bulk: non-sensitive AS Watson breadcrumb/CSS endpoints')
ON CONFLICT (finding_id) DO NOTHING;

UPDATE findings f
SET status = t.new_status,
    likely_program_outcome = t.outcome,
    triage_reasoning = t.reason
FROM _triage_batch t
WHERE f.id = t.finding_id;

-- Sanity check before commit
SELECT new_status, outcome, count(*)
FROM _triage_batch
GROUP BY new_status, outcome
ORDER BY 1,2;

COMMIT;
