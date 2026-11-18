-- Schema mirroring docs/LIVE_TEST_LOG.md's shape: raw timestamped app log lines
-- captured during deliberate live-production tests (see the project rules). This is
-- the most naturally timeseries-shaped data in the project -- a real candidate
-- for eventually replacing the flat-file capture if volume ever grows.

CREATE TABLE live_test_capture_sessions (
    id          SERIAL PRIMARY KEY,
    label       TEXT NOT NULL,        -- e.g. "Resilience tests 1-4: baseline + attestation submission"
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    stopped_at  TIMESTAMPTZ
);

CREATE TABLE live_test_events (
    id          BIGSERIAL PRIMARY KEY,
    session_id  INTEGER REFERENCES live_test_capture_sessions(id) ON DELETE SET NULL,
    event_time  TIMESTAMPTZ NOT NULL,
    message     TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_live_test_events_event_time ON live_test_events(event_time);
CREATE INDEX idx_live_test_events_session_id ON live_test_events(session_id);
