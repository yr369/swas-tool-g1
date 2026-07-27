-- target_intelligence_migration.sql
--
-- Two tables backing target_intelligence.py:
--
-- 1. target_intelligence: one row per scope_target, holding its
--    generated attack persona and rolling technique-outcome memory.
-- 2. cross_target_patterns: append-only log of vuln-type + tech-stack
--    pairings seen on a project, so other targets sharing that stack
--    can be flagged with a hint.
--
-- Manual migration - run per the project's standard process:
--   docker compose exec -T postgres bash -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < target_intelligence_migration.sql

CREATE TABLE IF NOT EXISTS target_intelligence (
    id                    SERIAL PRIMARY KEY,
    target_id             INTEGER NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    persona               TEXT,
    persona_generated_at  TIMESTAMPTZ,
    technique_notes       JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (target_id)
);

CREATE TABLE IF NOT EXISTS cross_target_patterns (
    id                    SERIAL PRIMARY KEY,
    project_id            INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    vuln_type             TEXT NOT NULL,
    tech_stack_signature  TEXT NOT NULL,
    source_target_id      INTEGER REFERENCES scope_targets(id) ON DELETE SET NULL,
    note                  TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cross_target_patterns_lookup
    ON cross_target_patterns (project_id, tech_stack_signature);

-- Fill the `recorded_at` field target_intelligence.py leaves as NULL on
-- insert (jsonb has no `now()` default per-element) - this trigger
-- stamps it server-side so ORDER BY recorded_at in
-- record_technique_outcome() has a real value to sort on.
CREATE OR REPLACE FUNCTION stamp_technique_notes_recorded_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.technique_notes := (
        SELECT jsonb_agg(
            CASE WHEN elem->>'recorded_at' IS NULL
                 THEN elem || jsonb_build_object('recorded_at', now())
                 ELSE elem
            END
        )
        FROM jsonb_array_elements(NEW.technique_notes) AS elem
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_stamp_technique_notes ON target_intelligence;
CREATE TRIGGER trg_stamp_technique_notes
    BEFORE INSERT OR UPDATE ON target_intelligence
    FOR EACH ROW
    WHEN (NEW.technique_notes IS NOT NULL AND jsonb_array_length(NEW.technique_notes) > 0)
    EXECUTE FUNCTION stamp_technique_notes_recorded_at();
