CREATE TABLE scheduler_control_pool_expansion_guard (
    valid INTEGER NOT NULL CHECK(valid = 1)
) STRICT;

INSERT INTO scheduler_control_pool_expansion_guard(valid)
SELECT CASE WHEN (
    SELECT group_concat(identity, ',')
    FROM (
        SELECT id || ':' || lane || ':' || position AS identity
        FROM scheduler_slots
        ORDER BY id
    )
) = 'control-1:control:1,hands-off-1:hands-off:1,homelab-1:homelab:1,homelab-2:homelab:2,homelab-3:homelab:3,personal-1:personal:1,personal-2:personal:2,personal-3:personal:3,tensorhost-1:tensorhost:1,tensorhost-2:tensorhost:2,tensorhost-3:tensorhost:3'
AND (SELECT count(*) FROM scheduler_slots) = 11
AND NOT EXISTS (
    SELECT 1 FROM scheduler_slots
    WHERE state != 'clear' OR active_assignment_id IS NOT NULL OR
          active_work_id IS NOT NULL OR owner_id IS NOT NULL OR
          attempt IS NOT NULL OR fence_token IS NOT NULL
)
AND NOT EXISTS (
    SELECT 1 FROM scheduler_assignments WHERE state = 'active'
)
AND NOT EXISTS (
    SELECT 1 FROM opencode_deliveries
    WHERE lease_state IN ('active', 'aborting')
)
THEN 1 ELSE 0 END;
DROP TABLE scheduler_control_pool_expansion_guard;

DROP TRIGGER scheduler_slot_topology_rejects_insert;
INSERT INTO scheduler_slots(id, lane, position, state) VALUES
    ('control-2', 'control', 2, 'clear'),
    ('control-3', 'control', 3, 'clear');
CREATE TRIGGER scheduler_slot_topology_rejects_insert
BEFORE INSERT ON scheduler_slots BEGIN
    SELECT RAISE(ABORT, 'scheduler slot topology is immutable');
END;
