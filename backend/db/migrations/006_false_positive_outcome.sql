-- 006_false_positive_outcome.sql
-- Adds 'false_positive' as a loggable real-world outcome on
-- finding_outcomes.outcome. Previously the closest option was
-- 'rejected'/'not_applicable', which conflates "the program rejected it
-- for policy reasons" with "this was never actually a real bug" - two
-- very different signals for the triage learning loop (see
-- finding_outcomes' purpose: feeding future triage.py confidence).
-- Idempotent, same pattern as prior migrations.

ALTER TABLE finding_outcomes DROP CONSTRAINT IF EXISTS finding_outcomes_outcome_check;
ALTER TABLE finding_outcomes ADD CONSTRAINT finding_outcomes_outcome_check
    CHECK (outcome IN ('accepted', 'duplicate', 'rejected', 'informative', 'not_applicable', 'no_response', 'false_positive'));
