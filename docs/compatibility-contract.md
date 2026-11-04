# Compatibility contract

This contract records the observable behaviours Rig v2 must satisfy before it
can replace Rig v1. It is a target for later acceptance tests, not a claim that
the bootstrap implements these behaviours.

## Control and isolation

- Trust is secure by default; policy-rejected work is terminal until explicitly
  changed by an operator.
- `rigd` alone writes state and mutates backend/tmux. `rigctl` uses a private
  Unix socket; the cockpit is read-only.
- v2 has a separate repo, port, tmux namespace, state directory, and `HOME`.

## Lifecycle

- Start and stop operations are idempotent and expose explicit states.
- Controller, backend, terminal sessions, and workers have separately visible
  health; one is never inferred solely from another.
- Recovery after controller or machine restart uses durable state.
- Repeated deterministic failures trip a no-progress circuit breaker.

## Dispatch and ownership

- A unit of work has one durable identifier and at most one active scope owner.
- Claims and releases are atomic and survive process interruption.
- Exactly five lanes are visible. TensorHost, Home Lab, and Personal each have
  a three-slot LRU workspace pool; Control and Hands-off are singletons.
- Queued work remains ordered and inspectable across restarts.
- Scope ownership is exact and fenced; stale owners cannot write.
- Claims happen before transport, and scope release follows durable outcome
  recording.
- Automated dispatch passes through classification and policy enforcement.
- Work rejected by policy is terminal until explicitly changed by an operator.

## Completion and failure

- Completion is recorded exactly once for a durable work identifier.
- Completion is registered before transport and delivered exactly once only after
  scope release.
- Duplicate callbacks are safe and do not duplicate downstream effects.
- Ambiguous transport is `delivery_unknown` and is never blindly retried.
- Transient failures have bounded retries with recorded reasons.
- Deterministic or permission failures stop without blind retry.
- Interrupted work becomes recoverable or terminal; it cannot remain silently
  active forever.
- Recovery thresholds, retry limits, and bounded escalation are explicit.

## Visibility and control

- `rigctl status` and the cockpit derive their view from the same state source.
- The cockpit never repairs or mutates state directly.
- There is no polling loop; events, callbacks, leases/timers, and explicit
  operator requests drive progress.
- Attention requiring an operator is distinguishable from automatic recovery.
- Recent state transitions are available through an append-only event history.

## Security and migration

- Secrets, browser profiles, sessions, and live runtime data stay outside Git.
- Isolated workers cannot escape their declared filesystem and tool boundaries.
- Migration starts from a snapshot and can roll back to Rig v1 without
  overwriting the snapshot.
- No v2 component touches live Rig v1 state during development or shadow runs.
- Releases are immutable and shadow migration precedes attended cutover.

Milestone 10 proves these properties only with the explicit minimal synthetic
compatibility fixture documented in `migration-rehearsal.md`. It intentionally
does not implement, select, or authorize a live Rig v1 exporter or cutover.
