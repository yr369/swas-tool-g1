-- 019_project_policy_exclusions.sql
-- Program-specific policy exclusions, fed into triage.py's prompt
-- alongside its existing GENERIC policy-exclusion guidance (see
-- _TRIAGE_PROMPT in triage.py - it already tells the model "DoS,
-- self-XSS, open redirects, etc. are usually excluded" as general bug
-- bounty knowledge). This table-column pair lets a specific program's
-- actual, real published policy override or extend that generic
-- knowledge - e.g. a program that explicitly DOES pay for rate-limit
-- issues, or one with unusual additional exclusions the generic list
-- doesn't know about.
--
-- policy_raw_text: what you pasted in (kept verbatim for re-parsing
-- later or just re-reading what you gave it).
-- policy_exclusions: Gemini's structured extraction, [{"category":
-- str, "reason": str}, ...] - NULL until parsed at least once.
-- policy_parsed_at: NULL until the first successful parse; lets the UI
-- show "never parsed" vs "parsed on <date>, re-parse if the policy
-- changed".
ALTER TABLE projects ADD COLUMN IF NOT EXISTS policy_raw_text TEXT;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS policy_exclusions JSONB;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS policy_parsed_at TIMESTAMPTZ;
