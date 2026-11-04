# Deterministic test contract

This document defines the acceptance-test boundary for Fugue. It is
behavioral: implementation modules and class names may change, but the
observable invariants below may not. Tests must run against isolated temporary
directories and fakes. They must never inspect, start, stop, or mutate Rig v1,
the live backend, real tmux sessions, or the user's real runtime directories.

## Test levels

1. **Pure model tests** exercise lifecycle decisions and state transitions with
   no processes, sockets, wall-clock time, or filesystem access.
2. **Store tests** use one temporary SQLite database and real transactions.
   Each test creates and destroys its own directory.
3. **Controller tests** use fake backend, terminal, notifier, policy, and clock
   implementations. They execute scheduled work explicitly rather than sleep.
4. **Isolated integration tests** may start synthetic processes only under a
   temporary directory, with test-specific ports and session names. They are a
   later milestone and must be opt-in until their containment is reviewed.
5. **Migration tests** consume immutable synthetic snapshots. They never read a
   running or user-selected Rig v1 directory.

The default offline command remains:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Required deterministic seams

Before a behavior is implemented, its milestone must expose these replaceable
boundaries to the test harness:

- A manual monotonic clock and wall-clock source. Tests advance time directly;
  production code does not call `sleep` in a tested decision path.
- A deterministic identifier source. Tests supply work, attempt, session, and
  event identifiers instead of accepting random UUIDs.
- Fake backend and terminal adapters that record commands and return scripted
  success, transient failure, deterministic failure, timeout, or crash results.
- A fake notifier/callback sink that records stable idempotency keys.
- An explicit scheduler/drain hook so a test can run one queued action or drain
  all ready actions without polling.
- A fault-injection boundary around transaction commit, process launch, mode
  switch, callback delivery, and migration checkpoint writes.
- A fresh temporary database and runtime root per test.

Tests assert durable state, emitted events, and adapter calls. They must not
assert incidental logging text, private function calls, exact SQL, thread
timing, or implementation-specific class names.

## Lifecycle state contract

The controller exposes explicit lifecycle states equivalent to `STOPPED`,
`STARTING`, `RUNNING`, `SWITCHING`, `STOPPING`, and `DEGRADED` or `FAULTED`.
Backend, terminal, and worker health are separately observable. A controller
must not infer that every component is healthy from one process being alive.

### Transition cases

| Case | Stimulus | Required result |
|---|---|---|
| Cold start, secure and disarmed | Start from empty durable state | One controller owner is recorded; no backend or worker is launched; state reaches `RUNNING` in secure/disarmed mode |
| Duplicate start | Submit start twice | Second request is an idempotent no-op; exactly one backend owner and one start transition exist |
| Normal stop | Stop a quiescent controller | State passes through `STOPPING` to `STOPPED`; owned resources are released once |
| Duplicate stop | Submit stop while stopped or stopping | No duplicate release, callback, or adapter stop call occurs |
| Start failure | Backend fake returns a deterministic failure | Controller reaches `FAULTED`; cause and attention state are durable; no blind retry is scheduled |
| Partial start failure | Backend starts and terminal creation fails | Compensation stops only resources owned by this attempt; final state is durable and recoverable |
| Controller crash | Fail after durable intent but before external action result | On reopen, reconciliation performs at most one missing action and never creates a second owner |
| Backend crash | Backend health changes while controller remains alive | Backend health is unhealthy independently; controller enters recovery or fault state according to policy |
| Machine restart | Reopen the database with no in-memory state | Durable lifecycle, queue, ownership, retry, and attention state are reconstructed exactly |

Every accepted transition appends one event containing a stable event ID,
entity ID, previous state, new state, reason, and timestamp from the injected
clock. Rejected transitions change neither state nor event history.

## Client attachment and shutdown

Client attachment is reference-counted durably or derived from durable leases;
it is not guessed from a terminal process.

- Attach two clients, detach one, and assert the controller and backend remain
  running with one client visible.
- Detach the final client and assert exactly the configured final-client action:
  either clean shutdown or continued headless operation. The product decision
  must be explicit in configuration and recorded in an event.
- Deliver the same detach twice and assert the count never goes negative and no
  second shutdown begins.
- Crash one client without detach, advance the manual clock beyond its lease,
  run one reconciliation step, and assert it is expired once.
- Attach a new client while final-client shutdown is pending and assert the
  shutdown is cancelled or fenced according to the documented policy, without
  racing into a partial stop.

## Secure and insecure mode switching

Mode switching is fenced and serialized. New dispatch cannot cross the fence
while a switch is in progress.

- A no-op request for the current mode emits no adapter call.
- A secure-to-insecure and insecure-to-secure switch each enter `SWITCHING`,
  verify quiescence, apply policy and adapter changes, then return to `RUNNING`.
- A switch with active work is rejected or waits durably according to the
  documented policy; it never silently reclassifies active work.
- Queue work submitted during the fence remains ordered and is classified under
  the mode active when the fence is released.
- Failure before the commit point leaves the prior mode authoritative.
- Failure after an external side effect invokes compensation and records either
  the restored prior mode or a `FAULTED` state requiring attention.
- Restart at every durable switch checkpoint converges to one mode and one
  backend owner; it cannot launch both secure and insecure workers.
- A secure and disarmed cold start launches no delegated worker.

## Queue and ownership

The durable queue is FIFO among ready items with the same priority. A unit of
work has one stable ID. A scope has at most one active owner.

- Enqueue A, B, and C in separate committed calls, reopen the store, and assert
  dispatch order A, B, C.
- Roll back an enqueue transaction and assert the item and event are absent.
- Have two independent store connections claim the same exact scope; exactly
  one succeeds and the loser receives a conflict without retry side effects.
- Claims for documented non-overlapping scopes may coexist.
- Repeating a claim with the same work and idempotency key returns the original
  result without creating another claim event.
- Release requires the matching owner and attempt. A stale or foreign release
  changes nothing.
- Crash after a claim commit, reopen the store, expire or reconcile the claim,
  and assert the work becomes recoverable exactly once.
- Terminal policy rejection is durable and is not automatically requeued.
- A transient dispatch failure increments a bounded attempt count and preserves
  FIFO position according to the documented retry policy.

## Completion callbacks

Completion is accepted only for the matching work ID and attempt, and only after
the matching scope release is durably committed.

- Record completion twice with the same idempotency key; one completion and one
  downstream callback intent exist.
- Deliver one callback successfully, crash before acknowledging delivery, then
  retry. The sink sees the same idempotency key and downstream effects occur
  once.
- A callback for an unknown work ID, stale attempt, or still-owned scope is
  rejected without advancing work state.
- Callback failure does not roll back the completed work. It creates a bounded,
  inspectable delivery retry.
- Deterministic callback rejection becomes terminal and visible as operator
  attention; it does not loop.
- Callback order for multiple completions is stable and documented.

## Circuit breaker and retry classification

Retry decisions use structured failure classes, not matching human log text.

- Transient failures schedule retries using the injected clock, stop at the
  configured maximum, and persist attempt number and reason.
- Deterministic, permission, policy, and invalid-input failures do not retry.
- N identical no-progress results within the configured window open the breaker
  exactly at threshold N.
- While open, dispatch invokes no backend action and returns a durable reason.
- Advancing the manual clock to half-open permits exactly one probe across
  concurrent dispatchers.
- A successful probe closes the breaker and resets the no-progress series.
- A failed probe reopens it without a retry storm.
- Restart while open preserves its deadline and counters.
- Progress is defined by a durable state change, not output volume or repeated
  status messages.

## Migration

Migration is snapshot-based, versioned, transactional, and repeatable.

- Import a minimal valid synthetic v1 snapshot and assert the exact normalized
  v2 state and event history.
- Import a maximal fixture containing queued, active, failed, callback-pending,
  and unknown legacy records; unknown data is reported, not silently discarded.
- Re-run the same migration ID and checksum; result is an idempotent no-op.
- Reuse the migration ID with different content; migration is rejected.
- Inject failure at every checkpoint and assert the database is either entirely
  pre-migration or resumable from a documented committed checkpoint.
- Reject unsupported schema versions, malformed records, path traversal,
  symlinks escaping the snapshot, and changes to snapshot files during import.
- Assert source snapshots remain byte-for-byte unchanged.
- Generate and test a rollback plan without writing into Rig v1.

Golden migration fixtures must be synthetic, small, reviewable, and contain no
credentials, browser data, conversation content, or copied live state.

## Crash consistency matrix

For each operation below, inject a crash immediately before the durable intent,
after intent commit, after external action, and after result commit:

| Operation | Convergence invariant |
|---|---|
| Start backend | At most one owned backend; durable state explains whether reconciliation is needed |
| Stop backend | A stopped resource is not restarted unless lifecycle intent still requires it |
| Claim scope | At most one owner; queued work is neither lost nor dispatched twice |
| Release scope | Release is idempotent and completion cannot precede it |
| Switch mode | One authoritative mode; fence remains until convergence |
| Send callback | Stable delivery key; downstream effect at most once |
| Open/close breaker | Retry permission matches durable breaker state |
| Migration checkpoint | No mixed schema or partially imported logical record |

Each crash test creates a new controller instance against the same temporary
database. It must not preserve Python objects from the crashed instance.

## Cockpit/read-model boundary

The renderer receives snapshots or subscribes to events. It has no mutation,
repair, dispatch, callback, process, or database-write capability.

- Render every lifecycle and attention state from a fixed snapshot.
- Re-rendering the same snapshot produces the same semantic output.
- Simulate stale and disconnected snapshots without initiating recovery.
- Assert all keyboard actions route through the public controller client.
- A renderer exception changes no controller or store state.

## Clean source/runtime separation

- Run every command with `HOME`, runtime root, cache root, log root, current
  directory, and temporary database redirected into a fresh test directory.
- Snapshot the repository tree before and after start, stop, status, migration,
  crash recovery, and test execution; no tracked or untracked runtime artifact
  may appear in the checkout.
- Assert SQLite database, WAL, shared-memory, locks, PIDs, logs, caches, and
  generated state appear only beneath their configured runtime roots.
- Assert path calculation itself performs no I/O.
- Reject runtime roots that are the repository, inside the repository, symlinks
  into it, or symlinks outside an approved root.
- Validate restrictive permissions without depending on the process's ambient
  umask.

The current harness enforces bootstrap path purity and scans the checkout for
common runtime artifacts. Later milestones must extend this section with
command-level before/after snapshots.

## Milestone gates

A production milestone is incomplete until all earlier relevant tests pass and
the new behavioral cases are executable. Skipped tests do not satisfy a gate.
Tests for interfaces that do not yet exist remain in this contract rather than
as permanently skipped executable tests.

| Milestone | Required executable sections |
|---|---|
| Bootstrap | Inert CLI; pure runtime paths; source/runtime artifact scan |
| State store | Queue and ownership; event history; store-level crash points |
| Controller lifecycle | Lifecycle; client attachment; backend ownership |
| Mode and policy | Secure/insecure switching; fences; terminal rejection |
| Dispatch and callbacks | FIFO dispatch; release-before-completion; callback idempotency |
| Recovery | Circuit breaker; restart convergence; full crash matrix |
| Migration | All synthetic snapshot and rollback-plan cases |
| Cockpit | Read-model boundary; no recovery action from rendering |
| Cutover candidate | Entire offline suite plus separately reviewed isolated integration suite |

Every test failure must report the work/entity ID, prior state, attempted
transition, and durable events observed. This keeps failures diagnosable without
requiring access to live logs or state.
