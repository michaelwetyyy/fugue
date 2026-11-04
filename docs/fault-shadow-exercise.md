# Deterministic fault and shadow exercise

Milestone 9 is exercised entirely against fresh temporary directories, the
disabled transport/callback boundary, manual clocks, and synthetic child
processes. It never selects a user runtime, Rig v1 path, live OpenCode process,
tmux session, or callback endpoint.

Run the focused warning-strict gate with:

```bash
PYTHONPATH=src python3 -W error -m unittest tests.fault_shadow_suite -v
```

The suite reports ordinary `unittest` pass/fail evidence and covers:

| Fault class | Executable evidence |
|---|---|
| Daemon/controller crash and replacement | hard-kill a synthetic durable daemon, prove the old PID is gone, replace its stale socket, and reopen the same private database |
| Durable convergence | preserve idempotent outcomes, queue/ownership state, exact five-lane/eleven-slot topology, and one transport attempt across restart |
| Stale authority | reject stale recovery generations, authority leases, assignment attempts, and fence tokens without side effects |
| Duplicate delivery | race duplicate dispatch requests and repeat completion/callback reconciliation with stable durable identities |
| Unknown delivery and callback timeout | convert post-intent disconnect or interrupted callback delivery to terminal visible `delivery_unknown` without resend |
| Process containment | kill synthetic process groups on timeout and adapter-parent death |
| Clock skew | use monotonic time within an epoch despite wall-clock rollback/forward skew, and the persisted dual-clock restart rule across epochs |
| Same-database contention | race two independent store instances, preserve exactly one winner, restart, and accept only the exact fenced recovery |
| Snapshot damage | remove or corrupt public snapshot sections and render explicit degraded/unavailable state while preserving five lanes and eleven slots |
| Schema shadow restart | apply migrations `001` through `009` one at a time, close/reopen SQLite after every migration, and prove synthetic state survives |
| Isolation | assert production transport and callback mutation surfaces remain disabled and the source tree receives no runtime artifacts |

The focused gate complements, and does not replace, the full offline suite:

```bash
PYTHONPATH=src python3 -W error -m unittest discover -s tests -v
```
