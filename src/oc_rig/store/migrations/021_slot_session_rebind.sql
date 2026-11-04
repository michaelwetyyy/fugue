DROP TRIGGER opencode_slot_generation_appends_once;

CREATE TRIGGER opencode_slot_generation_appends_once
BEFORE INSERT ON opencode_slot_generations
WHEN NOT (
    (
        NEW.generation = 1 AND NOT EXISTS (
            SELECT 1 FROM opencode_slot_generations
            WHERE slot_id = NEW.slot_id
        )
    ) OR (
        NEW.generation = (
            SELECT MAX(previous.generation) + 1
            FROM opencode_slot_generations AS previous
            WHERE previous.slot_id = NEW.slot_id
        ) AND
        NEW.worker = (
            SELECT previous.worker
            FROM opencode_slot_generations AS previous
            WHERE previous.slot_id = NEW.slot_id
            ORDER BY previous.generation DESC LIMIT 1
        ) AND (
            NEW.session_id = (
                SELECT previous.session_id
                FROM opencode_slot_generations AS previous
                WHERE previous.slot_id = NEW.slot_id
                ORDER BY previous.generation DESC LIMIT 1
            ) OR NOT EXISTS (
                SELECT 1 FROM opencode_deliveries AS delivery
                WHERE delivery.slot_id = NEW.slot_id
                  AND delivery.lease_state IN ('active','aborting')
            )
        )
    )
) BEGIN
    SELECT RAISE(ABORT, 'opencode slot generation must append exactly once');
END;
