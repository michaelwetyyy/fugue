# Milestones

1. **Bootstrap — complete:** isolated v2 repository/runtime and inert entry points.
2. **State core — complete:** SQLite schema, FIFO queue, events, claims, fences,
   sessions, outcomes, and restart markers.
3. **Protocol boundary — complete:** private Unix socket and thin `rigctl` client.
4. **Trust and scope — complete:** secure-default policy, exact scopes, terminal rejection.
5. **Five-lane scheduler — complete:** three three-slot workspace pools plus
   singleton Control and Hands-off lanes.
6. **Adapters and transport — complete:** isolated backend/tmux adapters and
   delivery states.
7. **Completion and recovery — complete:** ordering, ambiguity reconciliation, bounded
   retries, thresholds, and escalation.
8. **Read-only cockpit — complete:** authenticated, bounded durable projection without
   direct database access, mutation, controller actions, or polling.
9. **Fault and shadow exercise — complete:** deterministic synthetic restart,
   persistence, fencing, duplicate, timeout, process, clock, socket, concurrency,
   snapshot-degradation, and migrations 001–009 exercises.
10. **Migration rehearsal — complete:** deterministic immutable wheel and hash
    manifest, strict minimal synthetic compatibility export, transactional
    import, byte-hashed snapshots, isolated disabled-adapter candidate start,
    abort matrix, and byte-identical rollback without a live path.
11. **Live local-user wiring — complete:** explicit pinned loopback OpenCode
    configuration, store-backed dispatch, daemon-owned SSE completion, abort
    fencing, restart-no-resend, and offline fake-backend launchd coverage.
12. **Attended cutover:** authorized switch with rollback data retained.
