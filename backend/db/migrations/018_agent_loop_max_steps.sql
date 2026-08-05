-- 018_agent_loop_max_steps.sql
-- Per-project override for agent_loop.py's investigation step budget.
--
-- Same pattern as preferred_ai_model (batch 26 item 3): nullable, no
-- default beyond NULL. NULL means "use the hardcoded default"
-- (_DEFAULT_MAX_STEPS in agent_loop.py, bumped 6->12 alongside this
-- migration) - this column only exists to let a specific project run
-- deeper (up to 25) when its auth flows/chains genuinely need more
-- steps to reach a boundary, without raising the default for every
-- project and burning Gemini quota on runs that didn't need it.
--
-- The CHECK constraint (1-25) is a second, independent enforcement of
-- the same hard ceiling agent_loop.py's Python loop already enforces in
-- code (_HARD_STEP_CEILING) - a bad value can't even be written to the
-- database, let alone reach the loop.
ALTER TABLE projects ADD COLUMN IF NOT EXISTS agent_loop_max_steps INTEGER
    CHECK (agent_loop_max_steps IS NULL OR (agent_loop_max_steps BETWEEN 1 AND 25));
