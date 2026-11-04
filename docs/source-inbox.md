# Source inbox projection

## Decision

Fugue may show source-bound completion nudges and other messages, but it does
not own their queue. The controller and the source client's App Server remain
authoritative for admission, ordering, turn association, commit and failure.
The cockpit renders a bounded metadata-only projection.

Source clients are spatial pools rather than single nodes. The Codex pool
contains one triangular-pyramid node per visible Codex thread/task. Future
clients such as Claude use separate pools without merging their thread identity
or delivery authority.

Clicking a source-thread pyramid opens that exact thread's right-side Source
inbox. Each visible item contains only a stable item ID, kind, origin, optional
work ID, delivery state, queued time and bounded reason. Prompt text, result
text, transcripts, credentials, delivery keys and arbitrary App Server items are
excluded.
Return edges terminate at the destination thread node, not at an aggregate
Codex node.

## Delivery semantics

Per-thread activity and delivery state are separate:

- An active source turn does not require the sender to wait until the agent is
  idle. App Server can accept tool output for the active turn, and `turn/steer`
  can append user input to that in-flight turn.
- Accepted or queued is not the same as committed. The projection keeps those
  states distinct and never claims delivery from thread activity alone.
- If no compatible turn is active, the integration needs an explicit durable
  route and later `turn/start`; Fugue does not infer that a message was applied.
- Delivery uncertainty remains visible and is never blindly retried.
- A message belongs to one exact destination thread. Pool membership is visual
  grouping only and never authorizes rerouting to another idle Codex thread.

Reference: [Codex App Server](https://learn.chatgpt.com/docs/app-server).

## Per-thread controller inbox read

The live inbox is selected-thread state, not a singleton field in the global cockpit
snapshot. The authenticated controller socket exposes the read-only
`codex.source.inbox.v1` operation with exactly one parameter, the canonical lowercase
Codex thread UUID. The operation bypasses durable mutation dispatch and the idempotency
journal. It queries only callbacks joined to that exact private Codex return route and
returns at most twelve items plus one truncation sentinel used only to derive collection
metadata.

The initial live item scope is deliberately narrower than the future schema: only
`completion_nudge` items have a controller-owned durable delivery state today. Their
state mapping is conservative:

- callback `blocked` or `pending` -> inbox `queued`;
- callback `delivering` -> inbox `delivering`;
- callback `delivered` -> inbox `accepted`; and
- callback `attention` -> inbox `attention`.

`accepted` here means the callback transport has positive evidence that Codex accepted
or durably recorded the exact nudge. It does **not** mean the destination model rendered,
consumed or acted on it. The controller refuses to project mismatched callback/outbox
state or an incomplete durable callback/assignment join. Attention may expose only its
bounded reason. Callback result text, callback body, delivery key and thread content are
never selected by this read.

The existing `codex_source_routes` table authorizes an idle `turn/start`; its
`state='committed'` records controller route admission, not App Server delivery. Those
outbound source messages therefore remain absent from the live inbox until a separate
durable App Server receipt exists. The UI must not reinterpret route admission as
message commit.

The Tauri source bridge requests this controller projection only for the exact selected
thread, validates the response again, and separately asks App Server for metadata-only
thread runtime state. If App Server runtime metadata is unavailable, the durable inbox
remains available with runtime marked `unavailable`. Active turn identity continues to
come from explicit thread inspection and is not inferred from inbox activity. React
binds each inbox response to the selected thread and drops stale responses after a
selection change. A committed controller event-sequence change refreshes the selected
inbox; there is no inbox polling loop.

## Local Codex bridge contract

`ui/src-tauri/src/codex_source.rs` is the isolated bridge core. It launches the
configured Codex App Server over local stdio; it does not open a listener or
trust an executable discovered through `PATH`. Before launch it reads the
owner-only v2 deployment state and requires the configured executable to be
`/Applications/ChatGPT.app/Contents/Resources/codex`. The current owner, mode,
inode, size and SHA-256 must match the deployment pin, the volume UUID must be
canonical, and the file identity must remain stable while it is hashed. Cheap
identity checks are repeated before later requests. `HOME` and `CODEX_HOME`
come only from the authenticated deployment state and the child receives a
closed environment.

Each process connection performs exactly one App Server handshake:

1. send `initialize` with Fugue client identity;
2. validate the closed initialization response; and
3. send the `initialized` notification before any thread operation.

The bridge has no approval UI. Any server-initiated request—including an
approval or user-input request—is refused and poisons the connection. Unknown
response envelopes, notification methods, fields or runtime states also close
the connection instead of being guessed at.

## Read boundary

Routine discovery uses `thread/list` with a bounded page size and state-database
metadata, then projects only thread ID, name, working directory, source,
timestamps and runtime status. Prompt preview and turns are deliberately
dropped. `thread/read` always sends `includeTurns: false` for an ordinary
metadata refresh and rejects a non-empty `turns` result.
Every `thread/read` response is also bound back to the exact requested thread ID.
A syntactically valid response for a different thread is a protocol failure; Fugue must
not use another thread's runtime state for inbox display or idle-route admission.

Only an explicit thread inspection calls `thread/read` with
`includeTurns: true`. That response is returned as a non-cloneable inspection
value and is not retained by the bridge. It must remain in the selected panel's
memory: never add it to controller snapshots, graph nodes, logs, preferences,
crash reports or durable route records.

## Message boundary

Messages are bounded text inputs with caller-supplied canonical message IDs.
An active-thread send uses `turn/steer` and requires the exact
`expectedTurnId` obtained during explicit inspection. The bridge accepts the
result only when App Server returns that same turn ID.

An idle-thread send uses `turn/start` with `approvalPolicy: never`, but only
after `CommittedIdleRoute::from_controller_response` validates an exact durable
controller receipt for the same expected thread **and** caller-supplied message ID.
A committed receipt whose thread or message differs from the request is rejected as a
protocol violation. UI state alone cannot construct an idle route. The controller
integration must persist that route before calling the bridge.

Delivery transitions are explicit:

- `queued` — validated locally and presented to the bridge;
- `accepted` — the complete JSONL request was written and flushed;
- `committed` — App Server returned the exact expected success receipt;
- `failed` — validation failed or App Server proved rejection; and
- `unknown` — the request may have crossed the process boundary but no valid
  receipt was obtained.

An `unknown` result poisons the connection and is never retried automatically.
Recovery requires an operator or a separate durable reconciliation decision.

Selection itself is also an authority boundary. Changing the selected Codex thread
synchronously invalidates the previous inspection, inbox request and delivery receipt before
the new panel can render. A returned inspection must identify the exact selected thread, and
the composer re-checks that same thread binding immediately before dispatch. This prevents a
slow A -> B selection race from rendering A's transcript under B or sending through A's stale
authority. The selected panel prefers the exact per-thread inbox runtime status over the
broader thread-list status, including an explicit `unavailable` result.

The bridge core is intentionally separate from the Tauri command and React
wiring. Live integration keeps one synchronized, authenticated App Server
connection because notification subscriptions belong to that active transport.
A dedicated background stdout reader is the only consumer of App Server output:
it demultiplexes exact RPC responses from notifications while request writers
remain serialized. For status observation it validates the closed notification shape but serializes
only the method names `thread/status/changed`, `turn/started`, or `turn/completed`
into the bounded in-memory/UI change queue; thread/status/turn payload fields are
discarded before the Tauri command boundary. The UI performs one blocking wait on
that queue and refreshes bounded thread metadata after an event, without an interval
or timer. The TypeScript bridge keeps that destructive native wait module-global and
single-flight: overlapping React effect lifetimes await the same Promise, so Strict Mode
cleanup cannot consume an event in an abandoned native waiter. Only after the shared wait
settles may a new native wait be armed. Every accepted source-change notification and every explicit manual cockpit refresh also
invalidates/reloads the selected per-thread Source inbox, so an unchanged selected thread ID
cannot retain stale exact runtime or queue metadata after either recovery path. Selected-inbox reads are single-flight per thread: while one exact read is
in flight, any number of accepted refresh triggers collapse to one dirty follow-up read rather
than queueing redundant requests ahead of explicit inspection or message delivery. Because
the wait does not hold the request mutex, inspection and message RPCs continue
on the same subscribed connection. The in-memory transcript is still dropped
when the inspection panel closes.

## Durable inbox ownership proof

The controller's per-thread read is observational, but it still fails closed on durable
identity corruption. Completion discovery is anchored on completed local-route evidence by
work ID and generation independently of callback existence; the strict ownership proof is
then applied with fail-closed joins. A displayed completion nudge must prove one exact
ownership chain across the local Codex return route, transport delivery, completion
registration, completion event, callback registration, scheduler assignment attempt/fence,
scope claim attempt/fence, callback/outbox delivery key and aggregate work ID, and durable
completion result. The topology binding is earlier and narrower: an assigned worker's
`source_id` comes directly from its registered local Codex return route, but only after the
transport is rebound to the slot's exact current active assignment ID, attempt, fence,
owner, slot and work. A retry with no current transport therefore projects no prior-attempt
transport or source edge. Once the current transport exists, the exact worker-to-source edge
exists before any completion callback is created. This separation
ensures that deleting or cross-linking a callback/outbox row cannot make a completed local
route disappear into an authoritative empty result or suppress the live source binding.
Missing or cross-linked rows make the whole selected-thread inbox unavailable;
the reader does not silently drop the inconsistent item and continue. The hidden thirteenth
row used only to prove that the visible 12-item projection is capped is part of the same
ownership proof: all 13 fetched rows are validated, while only the first 12 may be emitted.
A corrupt sentinel therefore cannot influence `truncated` or `lower_bound` without failing
the entire read closed. The capped wire shape is exact: 12 visible items, `total = null`,
`total_status = capped`, `lower_bound = 13`, and `truncated = true`. Rust and TypeScript
validate that same live-endpoint shape and require every declared field to be present even
when its value is nullable (`total`, `work_id`, or `reason`); omission is a protocol failure,
not an implicit null. The Rust bridge uses the same durable identifier grammar as the
controller for `work_id`, including `/`, `@`, `*`, `?`, and `+`. The UI may say that no
source-bound messages are queued only for an exact zero-count result. Migration
026 supplies covering read-path indexes on `local_codex_return_routes(thread_id,
return_route_id)` and `completion_results(work_id, generation)` so this bounded read does not
depend on global-history scans while it holds controller serialization authority.

`callbacks.state = delivered` is exposed only as `accepted`. This means the local Codex
callback transport accepted/recorded the nudge; it is deliberately weaker than App Server
`committed` and never proves that the destination model rendered or consumed the message.

## Rollout compatibility

The earlier app-first prototype accepted an optional singleton `source_inbox` field in
the cockpit snapshot. That field remains parser-compatible for synthetic fixtures and
older controller/app combinations, but it is not the live authority for a selected
Codex thread. Production uses the explicit per-thread controller read described above. Inbox loading,
unsupported-controller, and integrity/protocol failure are distinct UI states: only an
exact failure envelope from the authenticated controller may activate the legacy singleton
compatibility field: `ok = false`, the exact conditional response shape contains `error`
and omits `result`, and the closed error code is `unknown_operation`. Missing fields,
`result: null`, or any response carrying both result and error are protocol failures rather
than evidence of unsupported-controller compatibility. Transport, integrity, binding, or protocol
failure must render Source inbox metadata as unavailable and must never be displayed as
an authoritative empty queue. A legacy singleton carrying `status: unavailable` is likewise
unavailable, never an empty or authoritative inbox. Topology routing follows the same exact
binding rule: a worker/source edge exists only when `worker.source_id` matches a currently
visible source thread; Fugue never falls back to the first visible Codex thread when that
binding is absent or outside the visible page. The legacy singleton deliberately keeps its historical collection semantics, including
partial/capped metadata that need not have the live endpoint's exact 12/13 shape; only the
explicit per-thread live parser enforces that newer contract. Fugue Dev may continue to use
synthetic snapshot metadata to validate interaction and layout without contacting live Codex.
Once mixed-version compatibility is no longer needed, the legacy singleton field can be
retired separately.
