CREATE TABLE llm_behaviour_settings (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    model TEXT NOT NULL,
    effort TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision >= 1),
    applied_idempotency_id TEXT NOT NULL UNIQUE,
    updated_at TEXT NOT NULL,
    CHECK(
        (model = 'opencode/muse-spark-1.3-contributor-free' AND
         effort IN ('minimal','low','medium','high','xhigh','max')) OR
        (model = 'opencode/muse-spark-1.2-contributor-free' AND
         effort IN ('minimal','low','medium','high','xhigh')) OR
        (model = 'opencode/ling-3.0-flash-fin-free' AND
         effort IN ('low','medium','high'))
    )
) STRICT;

INSERT INTO llm_behaviour_settings(
    singleton, model, effort, revision, applied_idempotency_id, updated_at
) VALUES (
    1, 'opencode/muse-spark-1.3-contributor-free', 'max', 1,
    'migration-018-default-muse-spark-1.3-max', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

CREATE TRIGGER llm_behaviour_singleton_is_immutable
BEFORE UPDATE OF singleton ON llm_behaviour_settings BEGIN
    SELECT RAISE(ABORT, 'LLM behaviour singleton is immutable');
END;

CREATE TRIGGER llm_behaviour_revision_is_monotonic
BEFORE UPDATE ON llm_behaviour_settings
WHEN NEW.revision != OLD.revision + 1 OR
     NEW.applied_idempotency_id = OLD.applied_idempotency_id OR
     NEW.updated_at <= OLD.updated_at
BEGIN
    SELECT RAISE(ABORT, 'LLM behaviour update lacks new durable authority');
END;

CREATE TRIGGER llm_behaviour_row_cannot_be_deleted
BEFORE DELETE ON llm_behaviour_settings BEGIN
    SELECT RAISE(ABORT, 'LLM behaviour authority cannot be deleted');
END;
