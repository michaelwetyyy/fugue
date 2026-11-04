# Fugue agent lifecycles

## Terms

Agent lifecycle is independent from trust mode, lane and controller arming.
Fugue remains secure by default and retains one durable owner for every scope.

- **Disposable** creates a fresh root session for one bounded task. Completion
  closes its descendants, deletes the isolated session and releases the scope.
- **Persistent** gives each exact repository and scope its own retained secure
  root session so an orchestrator can continue related work with context. It is
  never multiplexed with another scope. If that session is busy, Fugue reports
  busy rather than silently moving the turn to a different context. Each turn
  has independent admission, delivery and completion authority.

Both lifecycles may request bounded child agents. This is a capability of the
root task, not a relaxation of its trust policy.

The lifecycle also does not decide write authority. A `task` turn is
proposal-only; an explicitly selected `work` turn may finish through the local
exact-file write broker. Persistent and disposable roots can both use that
mode, and both retain the same bounded child-analysis capability.

The initial `patch` route is disposable-only. This prevents a retained worker
session from accumulating different slices of the same large file and silently
reconstructing material beyond any one admitted window. The full-file `work`
route retains its existing lifecycle choices.

## Child-agent contract

Fugue records child authorization in the admission decision and exposes only
OpenCode's Task tool to the admitted root. The backend registers one hidden
`fugue-child` profile. Descendants have no tools except the same bounded Task
route, allowing controlled branching without filesystem, shell, MCP or plugin
access.

1. A child inherits the root trust mode and classification.
2. Its prompt must remain within the parent's admitted material and scope.
3. The root remains the sole consolidation and completion owner.
4. One root turn has a shared ceiling of 12 descendant sessions and maximum
   depth 3, with the admitted root at depth 0. Every delegation prompt states
   its depth and remaining shared budget.
5. Completion freezes every descendant whose immutable parent chain belongs to
   the current root turn. Historical branches of a persistent root are
   excluded.
6. A child-enabled root cannot create a completion event until every frozen
   descendant is terminal and one deterministic no-tool consolidation turn has
   produced the exact authorized final. A turn with no children passes through
   without an extra prompt.
7. Late, missing, excessive, too-deep or malformed descendant sessions move the
   barrier to operator attention. A new descendant grafted beneath a historical
   branch is also attention rather than being silently excluded. An uncertain
   consolidation send is never replayed.
8. Disposable cleanup deletes descendants before deleting their root session,
   so children cannot become orphaned backend state.

The webview cannot choose the descendant profile or broaden its permissions.
Descendant registrations and the authorized root final are durable controller
state; raw descendant text and child transcripts are not persisted. The only
durable conversation-content exception is the root assignment's optional
completion snapshot: bounded text is sanitized before storage, tied to the
exact completion, exposed only through an explicit read-only archive route, and
never grants composer authority. The controller's completion authority enforces
the shared tree budget fail-closed; per-child scope subdivision remains a later
hardening phase.

Controller-created `agent_task`, `workspace_edit`, and `workspace_patch` capsules
use a stricter closure rule than ordinary child-enabled turns. They do not use
descendants while drafting. After the draft exists, the root must create exactly
four direct `fugue-child` reviewers together in one Task-bearing assistant
generation, one each for `correctness`, `security`,
`tests`, and `minimality`. Each initial child prompt starts with exactly one
`FUGUE_REVIEW_PROFILE:<profile>` marker. The controller rereads those bounded
initial prompts at the completion barrier and requires all four unique profiles,
direct parentage to the root, and no additional descendant. A duplicate,
missing, unknown, nested, or unreadable reviewer fails closed into barrier
attention. A task capsule that reaches a terminal root answer without creating
reviewers may close only as a failed completion; it can never be credited as
successful work. This review quorum is therefore controller authority rather
than prompt compliance.

For proposal-only `agent_task`, the consolidated assistant text must then pass a
separate 24 KiB controller parser for `fugue.handover/v1`. The model-authored
object has exactly `schema`, `status`, `summary`, `changes`, `reviews`,
`unresolved`, and `codex_actions`. `changes` contains only admitted
repository-relative paths and bounded diff hunks, `reviews` contains exactly the
four canonical profiles, and a `ready` handover has no unresolved finding. The
controller canonicalizes the validated JSON before persistence. Malformed or
out-of-scope successful output is recorded as failure instead of being exposed
as an authoritative proposal. `workspace_edit` and `workspace_patch` retain
their existing local broker schemas and receipts after the same four-review
closure gate.

## Persistent turns

Fugue displays the durable result on demand and never polls in the background.
Its bounded recent-task registry keeps up to twelve accepted references on the
local machine, making results discoverable after the drawer or app is closed.
After a persistent result completes, **Continue task** opens a new turn with
the repository, scope and lifecycle fixed to the existing conversation. The
objective may change and the turn is admitted again against the current file
capsule. Disposable tasks do not expose continuation.

Persistent results now expose an explicit retained-session close operation. The
client supplies only the existing GUI submission ID and reservation attempt; it
never supplies an OpenCode session ID or scope hash. The controller reconstructs
the exact accepted persistent task envelope from private durable submission
authority, resolves the retained root by its scope binding, and refuses closure
while any durable delivery lease still owns that session. It then revalidates
the root and all descendants as idle with clear todos, deletes descendants
deepest-first and the root last, and rereads backend state before committing
`closed`. A partial or uncertain delete is terminalized as `attention` rather
than retried blindly, and that retained scope is not reused. Persistent close
attention also enters the cockpit's global operator-attention collection under an
opaque local `persistent-N` identifier; the projection omits the scope hash,
OpenCode session ID and task content. The operation is idempotent across a
controller crash: an already-closed or attention-fenced session finalizes the
existing request reservation without another backend mutation. Hiding a result
drawer still does not delete durable authority.

Result reads expose only `active`, `closed`, `attention`, or `unavailable` as
coarse retained-session state. The task-result client requires a separate
confirmation action before close and removes continuation after a terminal close.
The topology cockpit itself remains observation-first and does not surface task
submission controls.

## Graphical boundary

The Tauri task-lifecycle bridge exposes fixed submit, result, and explicit-close
commands. It cannot select a socket, controller operation, worker identity, trust
mode, tool permission, retained session ID, scope hash, or delegation limit. All
input is bounded and revalidated by the controller before durable state is
created or an external deletion is attempted.
