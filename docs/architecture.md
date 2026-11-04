# Architecture

## Objective

Rig v2 is a replacement controller developed beside Rig v1. Until an attended
cutover, v2 uses a separate repository, ports, tmux namespace, state directory,
and `HOME`; it must not touch live v1 state. Releases are immutable, and shadow
migration is required before cutover.

## Component boundaries

`rigd` is the sole writer of the database and the sole component allowed to
mutate backend or tmux state. `rigctl` is a thin client on a private Unix
socket. The cockpit is a read-only projection; it performs no direct mutation.

## Modules

- **Protocol and client:** versioned messages over the private Unix socket.
- **State core:** SQLite transactions, FIFO queue, claims, sessions, retries,
  completion records, recovery markers, and append-only events.
- **Policy and trust:** secure-by-default classification and explicit scope.
- **Dispatcher:** exact scope creation, claim-before-transport, and scheduling.
- **Adapters:** isolated backend and terminal boundaries called only by `rigd`.
- **Transport/callbacks:** completion registration and explicit delivery states.
- **Recovery:** restart reconciliation, bounded retries, thresholds, and
  escalation.
- **Cockpit projection:** read-only lane, pool, queue, session, and attention
  state from the same source as `rigctl`.

## Dependency direction

The controller may depend on state, policy, and adapter interfaces. Adapters may
depend on external tools, but external tools must not call controller internals.
The cockpit and command-line client depend only on a public controller protocol.

## Scheduling and ownership

Exactly five lanes are visible. TensorHost, Home Lab, and Personal each have a
three-slot LRU workspace pool; Control and Hands-off are singletons. A work item
has one durable identifier, one exact scope, and at most one active owner.
Claims and releases are atomic and fenced; stale owners cannot write. The queue
is durable, FIFO, ordered, and inspectable across restarts.

Completion is registered before transport. The opt-in local-user OpenCode path
uses a store-backed slot reservation, authenticated loopback HTTP dispatch, and
a daemon-owned SSE monitor with bounded REST repair. Completion acceptance and
release of its exact slot reservation commit in the same store transaction;
restart repair also closes historical completed-registration lease seams.
Exhausting the fast SSE reconnect budget leaves the monitor visibly degraded
but alive: it retries without operator input on a capped slow backoff and clears
the controller-scoped backend attention only after authoritative REST repair.
Ambiguous transport becomes `delivery_unknown` and is never blindly retried;
restart reconciliation
retains in-flight and abort fences without resending. All unconfigured and
dedicated-service paths inject `DisabledAdapter`.

An optional direct-Codex return route is private controller metadata, carried
beside rather than inside the OpenCode task payload as the exact object
`{"kind":"local_codex","thread_id":"<canonical UUID>"}`. The route is bound
before transport sends. After the exact completion, scheduler assignment, and
scope release join, the durable callback outbox may invoke a pinned local
`codex queue` executable. Exit zero consumes the route; a timeout, non-zero
exit, crash after delivery start, or other ambiguous result becomes visible
`delivery_unknown` and is never resent. The thread ID is omitted from public
snapshots and worker content. Configuration requires explicit absolute paths
for the canonical Codex executable, local user home, and `CODEX_HOME`; it does
not modify Codex Desktop or reuse Rig v1 callback files.

For isolated OpenCode reviews, the completion transaction stores the bounded
terminal assistant text and its cryptographic identity bindings. Tool traces,
reasoning parts, raw backend transcripts, and child transcripts are never
persisted. Before an exact root assignment is released, Fugue may additionally
capture one bounded text-only completion snapshot from that root session. The
snapshot passes the same structural transcript projection plus durable content
scanning; sensitive or confusable visible text is replaced with a fixed
redaction marker before persistence. The immutable row is hash-bound to the
exact completion result, transport, work, generation, execution slot, and root
session. Cockpit snapshots expose only archive metadata; archived text requires
a separate explicit read and is permanently read-only, so it can never become a
composer destination. The local Codex nudge carries the exact
`completion-result-…` reference; retrieve it with `rigctl completion-result
<reference>` before continuing the workflow. Session cleanup is enqueued only
after that result, any available sanitized transcript snapshot, and the exact
completion release commit together. A backend transcript read failure does not
block completion and produces no archive row.

Child-enabled turns add a durable completion barrier before that transaction.
The controller freezes the current root turn's complete descendant tree, with a
shared ceiling of 12 descendant sessions and maximum depth 3 (root depth 0),
using backend parent identities rather than transcript inference. Historical
branches on persistent roots are excluded. All frozen descendants must be
terminal before the controller durably prepares and sends one deterministic
no-tool consolidation prompt. Only the assistant message parented by that
prompt may become the final result. Ordinary child-enabled turns with no
descendants authorize their original prompt-bound final directly.
Controller-created task capsules are stricter: their only descendants are the
four direct post-draft self-reviewers created in one Task-bearing assistant
generation (`correctness`, `security`, `tests`, and `minimality`), identified by
one concrete `FUGUE_REVIEW_PROFILE:<profile>`
marker in each initial child prompt. The controller requires exactly that unique
direct quorum before a successful task can reach consolidation; missing or
invalid review authority cannot be repaired by trusting the root's prose. A
terminal task with no reviewers is demoted to failed completion, while a
changed, too-deep, excessive, malformed, duplicated, nested, or unreadable
review set moves to attention. Any uncertain consolidation send also moves to
attention and cannot create a completion event. Database insertion and
transition guards independently prohibit child-bearing barriers from appearing
ready without passing through the frozen and fully terminal descendant states.

Secure-mode history is a separate trust domain. Conversation history produced
entirely inside secure sessions may be retained and compacted because every
input is admitted as PUBLIC or SANITIZED and the worker remains isolated.
Normal-mode sessions and legacy memory are never imported into that domain.
Durable secure memory is optional, compact, provenance-labelled, and confined
to the secure workspace; it is not a copy of raw prompts or tool transcripts.
Its generated worker policy has one source of truth shared by deployment and
runtime validation, so a deployment cannot silently weaken the admitted agent.
Interactive secure-workspace writes use canonical no-symlink traversal, scan
the complete resulting bytes, validate the closed PUBLIC/SANITIZED memory
schema, and replace the destination atomically. Attachments and other non-text
prompt parts fail closed rather than bypassing the text admission scan.
Session rotation is therefore a relevance and context-size decision, not a
requirement to discard already-admitted secure history.

Codex-facing implementation proposals reuse the GUI submission transaction:
exact regular UTF-8 files are captured into a PUBLIC capsule, lifecycle and
child authority are admitted durably, and a private completion route is bound
beside rather than inside worker content. The secure worker and descendants
remain no-tool except for the bounded Task route used for delegation. They can
return a patch proposal, but only after the controller-validated four-profile
self-review closure. Proposal-only `agent_task` results cross the boundary as a
canonical, at-most-24-KiB `fugue.handover/v1` object with exact outer keys
`schema`, `status`, `summary`, `changes`, `reviews`, `unresolved`, and
`codex_actions`; changed paths must belong to the admitted capsule and only
bounded diff hunks are accepted. A `ready` handover cannot contain unresolved
findings. The accountable Codex owner remains the only authority that may
inspect the live checkout, apply changes, run tests, or install a result.
Proposal capacity is the controller's logical lane reservation; the worker runs
in its isolated task session and does not depend on historical todos or status
in the lane's legacy display session.

Direct workspace work is a separate, explicit completion mode. The OpenCode
worker still receives no shell, filesystem, plugin or MCP tool; instead it
returns a closed JSON edit plan containing one complete UTF-8 replacement for
one declared existing file and its admitted preimage hash. A daemon-local
write broker recovers the absolute repository only from private submission
authority, validates every target before the first write, rejects links,
special files, changed preimages, undeclared paths and unsafe or oversized
content, then atomically swaps the file in place while preserving its mode. The edit is
idempotent when a postimage already landed, so completion repair can safely
finish after interruption. Only a content-free receipt enters the durable
completion/callback path. No worktree or Git commit is required, unrelated
dirty files are ignored. A clean validation rejection becomes a failed task and
releases its exact scope. Any error after the atomic commit boundary is instead
indeterminate: the completion is not finalized, the scope remains owned, and
restart repair inspects the plan-bound recovery file and exact postimage before
either completing or escalating.

The initial broker is macOS-only because it requires Darwin's atomic
`RENAME_SWAP`. Other platforms reject the write boundary; they do not fall back
to a non-atomic replacement.

Large PUBLIC files use a separate `workspace_patch` mode. The caller—not the
worker—selects one inclusive line window. Fugue receives only that bounded
window and its immutable manifest; the complete admitted preimage stays in the
controller's private durable submission authority for exact reconstruction and
crash recovery. The worker returns the path, full-preimage hash, exact window
range and hash, and replacement window in a closed JSON plan. The broker rejects
fuzzy or worker-selected ranges, reconstructs the whole postimage locally,
rescans it, and reuses the same atomic swap and indeterminate recovery boundary.
The first version is deliberately disposable, single-file and single-window.

Every retry records its reason and has a bounded budget. Deterministic,
permission, policy, and no-progress failures stop or trip an explicit circuit
breaker. Interrupted scopes become recoverable or terminal, never silently
active.

Post-acceptance session loss is reconciled per task. A pinned OpenCode
`session.deleted` event, or an exact omission during bounded connection-seam
read repair, marks only the matching accepted disposable delivery as a durable
`corpse` recovery observation. It does not degrade the controller, poll the
worker, release scope, synthesize completion or abort. A matching reappearance
returns the observation to productive active state, while a real completion
wins and closes the recovery evidence in the same completion transaction.
Persistent, delivery-unknown, aborting, cleanup and already-completed work are
ineligible for this automatic observation.

An exact idle event also performs one bounded reconciliation immediately. If
the registered disposable session remains present and idle with clear todos,
but has neither a terminal prompt-bound result nor a progressing child barrier,
the monitor arms one 30-second generation-fenced deadline. A matching final,
child progression, busy event, unregister or shutdown cancels it. Expiry makes
one authoritative recheck and records the same durable session recovery target
as `corpse`; there is no interval polling and no synthesized completion. The
recovery generation is the scheduler assignment attempt, not the unrelated
OpenCode slot generation, so cockpit colour and completion evidence join the
same authority.

## Delivery sequence

1. Specify state schema and protocol.
2. Implement state core and deterministic transitions.
3. Add isolated adapters, dispatch, callbacks, policy, and recovery.
4. Build the read-only cockpit projection.
5. Exercise faults and shadow migration against isolated instances.
6. Perform an attended, snapshot-backed, reversible cutover.
