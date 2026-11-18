-- Schema mirroring the project history shape: append-only narrative entries,
-- one per real event/change. Not the active system of record yet -- see
-- db/README.md (once written) for the migration plan, same as decisions.

CREATE TABLE milestones (
    id          SERIAL PRIMARY KEY,
    occurred_on DATE NOT NULL,
    title       TEXT NOT NULL,
    body        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_milestones_occurred_on ON milestones(occurred_on);
