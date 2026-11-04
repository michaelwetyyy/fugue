CREATE TABLE transport_adapter_selections (
    transport_id TEXT PRIMARY KEY REFERENCES transport_deliveries(id),
    adapter_kind TEXT NOT NULL CHECK(adapter_kind = 'opencode-http-sse-v1'),
    selected_at TEXT NOT NULL
) STRICT;
CREATE TRIGGER transport_adapter_selection_is_immutable
BEFORE UPDATE ON transport_adapter_selections BEGIN
    SELECT RAISE(ABORT, 'transport adapter selection is immutable');
END;
CREATE TRIGGER transport_adapter_selection_is_not_deleted
BEFORE DELETE ON transport_adapter_selections BEGIN
    SELECT RAISE(ABORT, 'transport adapter selection is immutable');
END;
