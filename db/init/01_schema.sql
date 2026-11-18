-- Schema for entropa's decision-outcomes tracking, mirroring the structure already
-- established in a project record (not published) (Expected proof -> Observed outcome -> Evidence).
-- This does not replace that file yet -- see db/README.md for the migration plan.

CREATE TYPE decision_status AS ENUM (
    'confirmed',
    'rejected',
    'needs_follow_up',
    'partial',
    'deferred'
);

CREATE TABLE decisions (
    id              SERIAL PRIMARY KEY,
    decided_on      DATE NOT NULL,
    title           TEXT NOT NULL,
    original_decision TEXT NOT NULL,
    reason          TEXT NOT NULL,
    expected_proof  TEXT NOT NULL,
    observed_outcome TEXT,
    status          decision_status NOT NULL DEFAULT 'deferred',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Evidence is one-to-many: a decision can have multiple evidence items
-- (test output, log excerpt, deploy revision, commit hash, screenshot link, etc.)
CREATE TABLE decision_evidence (
    id           SERIAL PRIMARY KEY,
    decision_id  INTEGER NOT NULL REFERENCES decisions(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,   -- 'test' | 'log' | 'command' | 'deploy_revision' | 'commit' | 'screenshot' | other
    detail       TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_decisions_status ON decisions(status);
CREATE INDEX idx_decisions_decided_on ON decisions(decided_on);
CREATE INDEX idx_decision_evidence_decision_id ON decision_evidence(decision_id);

-- Keep updated_at current on any row change.
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_decisions_updated_at
    BEFORE UPDATE ON decisions
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();
