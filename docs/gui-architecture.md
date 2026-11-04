# Fugue graphical cockpit architecture

## Decision

Fugue's primary product interface will be a cross-platform React and Tauri 2
desktop application. The existing single-pane terminal cockpit remains a small
recovery and diagnostic fallback. The graphical client is another projection
of the controller; it is not a second scheduler, ownership authority or repair
engine.

The cockpit is a graph-first visibility surface for work offloaded by Codex or another
source agent. It renders active worker and route topology, assigned work and
the immutable disposable/persistent lifecycle selected at admission, the
dispatch queue, attention, durable metrics and recent privacy-safe metadata
from the initial `cockpit.snapshot.v1` projection and the change-driven
`cockpit.watch.v1` feed. Assignment remains source-agent-owned. Fugue adds an
explicit, on-demand private plane for the selected source thread or worker:
bounded transcript inspection and an exact-destination, send-once composer.
General Settings can arm or disarm new OpenCode offloads, while LLM Behaviour
can apply one supported model/effort pair to future root dispatches. Fugue
cannot change trust mode, stop services, acknowledge attention or accept
credentials.

## Boundaries

```text
React webview
    │ fixed typed commands: lifecycle, cockpit watch, integration, LLM defaults,
    │ selected transcript/source inspection and exact-destination compose
    ▼
Tauri native bridge
    │ fixed local endpoint, 64 KiB frame limit, correlated protocol v1 request
    ▼
Fugue controller
    │ cockpit.snapshot.v1 / cockpit.watch.v1(after_event_sequence)
    ▼
Durable normalized snapshot
```

- The webview never receives a socket path and cannot select an endpoint.
- App launch validates and executes only the owner-controlled Fugue lifecycle
  wrapper, waits for the authenticated cockpit socket, then allows the initial
  snapshot. It cannot pass lifecycle arguments. Repeated starts reuse the exact
  running lifecycle.
- The native bridge exposes no general shell, opener, filesystem or network
  plugin. Its integration command accepts only a boolean desired state and can
  execute only the fixed owner-controlled `oc-integration arm|disarm` facade.
- After the initial snapshot, the webview holds exactly one authenticated wait
  carrying its last validated durable event sequence. The controller blocks
  without a timer and wakes the request only after a committed event advances
  that sequence, then returns a fresh normalized snapshot. The next wait starts
  only after the UI applies that snapshot. Manual refresh is recovery-only.
- Codex source runtime state has a separate event-driven feed on the same
  authenticated App Server transport used for source RPCs. One background
  stdout reader demultiplexes responses and notifications; only the closed
  metadata methods `thread/status/changed`, `turn/started`, and `turn/completed`
  enter a bounded in-memory wake queue, never their params. Each wake triggers
  one bounded `thread/list` refresh. The blocking UI wait does not hold request
  authority, so inspection and message RPCs remain available concurrently. No
  interval, timer, or cockpit event is used to keep Codex source badges current.
  Manual refresh remains the recovery path if that stream becomes unavailable.
- Default snapshot/watch responses remain metadata-only with
  `content_included=false`. An active worker transcript is fetched only after
  explicit selection, held in memory for five minutes, bounded by count and
  bytes, and never copied into graph or activity state. While that exact
  assignment stays selected, each newly validated Fugue event silently
  refreshes the bounded live transcript and preserves the prior bundle until
  its replacement validates; there is no refresh button, interval or polling
  loop. When an assignment completes, the controller can retain one immutable,
  bounded, text-only snapshot after durable content scanning and redaction. The
  graph snapshot carries only the latest archive metadata; selecting an idle
  worker performs a separate exact archive read. Archived bundles are visibly
  read-only and structurally have no composer route. Worker messages therefore
  remain possible only for an exact active slot, work and generation; source
  messages remain bound to the exact Codex thread and expected turn. Both live
  message paths are send-once with UUIDv4 idempotency and no automatic retry
  after uncertain delivery.
- The topology graph uses only normalized `worker_graph` relationships and
  privacy-safe component states. It never infers message content from an edge,
  and recent turns remain bounded metadata with `content_included=false`.
- The topology is rendered as a local Three.js scene with OrbitControls. Slow
  rotation stops under reduced-motion preference; left drag orbits, right drag
  pans, wheel/pinch zooms, and rendering is skipped while the document is
  hidden. Lit cubic nodes and a sparse world-space point field provide depth
  and parallax without a flat screen-space grid. Borderless, screen-facing DOM labels are
  projected from the 3D node positions and remain the accessible selection
  controls. WebGL failure leaves the metadata inspector available and reports
  the graph as unavailable.
- Settings is a three-section operational GUI. General shows current backend,
  callback and queue state and owns the one mutable system switch: OpenCode
  offload. Secure mode, bounded child agents, the direct file broker, the live
  change feed and background operation are visible as enabled, enforced
  guarantees rather than misleading preferences. GUI owns auto-rotation and
  speed, route-layer visibility, labels, depth points, halos and fog. Visual
  changes do not rebuild the scene or reset the camera. The app validates the
  closed preference shape before restoring it from local browser storage; no
  controller command, work content or transcript is stored with it. LLM
  Behaviour reads the controller's closed supported roster and requires an
  explicit confirmation before applying a model/effort pair to future root
  dispatches; running work and consolidation turns keep their admitted model.
- Integration state is read when Settings opens and after the user changes the
  offload switch. It is not polled. A confirmation step precedes either live
  state change. The native side resolves the account home through the OS user
  database rather than environment input, validates the fixed wrapper and a
  pinned integration-script digest, rejects symlinks or writable ancestry,
  uses an absolute interpreter, clears the child environment, serializes state
  mutations, bounds time and output, accepts only the closed secure status
  shape, and verifies that the requested state was reached.
- Assigned-worker lifecycle labels are joined from the immutable scheduler
  admission decision. Clear or unavailable slots carry no lifecycle; missing
  lifecycle on assigned work degrades paired-controller normalization.
- This additive v1 field uses an app-first lockstep upgrade: the new GUI accepts
  one legacy worker shape without the field and labels its lifecycle unavailable,
  then the paired controller release makes it mandatory. The controller must
  not be upgraded while an older GUI bundle remains installed.
- Historical cutover verification explicitly projects the pre-lifecycle v1
  shape so its pinned digest remains byte-for-byte stable; this compatibility
  path is not used for current cockpit responses.
- The Tauri capability applies only to the main window, grants no plugin/core
  permission set, and uses a deny-by-default content-security policy.
- The bridge verifies Unix socket ancestry, owner, mode, link count, inode and
  peer UID. On macOS it also requires the peer PID to be the process registered
  under Fugue's exact managed launchd label before accepting a response.
- Requests use the existing four-byte big-endian length prefix and 64 KiB
  maximum frame. Connect and write remain under a five-second monotonic
  deadline; the authenticated change wait deliberately has no read deadline
  and is released by either a committed event or controller shutdown. Responses
  must match both correlation identifiers. The webview then rejects unknown fields,
  malformed nested values, unsafe text, oversized collections and any recent
  turn payload that claims to include content.
- Native failures are reduced to three non-sensitive messages: unavailable,
  endpoint security validation, or invalid controller response.
- Rendering is defensive. Missing or malformed sections fail the refresh and
  leave any previous trusted snapshot visibly unchanged. A disconnected live
  feed also retains that snapshot, reports that live updates are paused and can
  be re-established with the recovery refresh action.
- Closing the main window is converted to hide; the event loop and managed
  background work stay alive. macOS Dock reopen shows and focuses that same
  window. The macOS application menu replaces Tauri's native predefined Quit
  item with a Fugue-owned `Cmd-Q` item that calls `AppHandle::exit(0)`, keeping
  explicit Quit distinct from window close. Native Dock/Apple-event Quit remains
  a separate upstream lifecycle limitation and is not used as the reliable exit
  path.

## Galaxy observability contract

The next graph phase is one cohesive projection change. Existing transcript,
composer, source-thread and LLM controls are preserved rather than rebuilt.

- Every admitted root and bounded descendant appears as a distinct node with
  an exact parent/delegation edge. Child topology comes from durable completion
  barriers; it is never inferred from transcript text.
- Each source-to-worker route passes through a small, label-free cylindrical
  Fugue proxy node. Dispatch and callback filters reuse one physical edge per
  relationship; direction is activity state and pulse behavior, not a second
  overlapping line. The proxy is a visual representation of the authenticated
  controller route, not a scheduler or independent agent.
- Pools are nested by source, workspace and role. Each visible pool is one
  translucent 3D ellipsoid fitted to the live positions and collision radii of
  its current members, with an enclosing OpenCode field around its populated
  subpools. This avoids concentric shell clutter and permanent node homes.
  Empty pools have no field or label; a one-member pool contracts to a compact
  local halo. Pool labels use distance-based level of detail: the enclosing
  OpenCode label is favoured at a distance and crossfades into individual
  subpool labels as the camera approaches.
- Waiting child nodes are green, parent recovery propagates orange, parent
  operator intervention propagates red, and terminal children are neutral
  grey. These colours derive only from controller-projected state.
- Node motion uses bounded force-directed physics: collision avoidance, linked
  ideal distance, intra-pool cohesion, inter-pool repulsion, damping and weak
  world gravity. Dragging imparts momentum; released nodes settle back into
  their relationships without resetting the camera.
- A committed activity sequence may pulse only its controller-projected route.
  Reduced-motion mode uses one static luminance step instead of animation.
- Activity entries use exact metadata in the form
  `origin → destination: event`, never message-content inference.
- The bounded work queue is a bottom-right fading overlay complementary to the
  bottom-left activity log; neither overlay changes scheduler authority.
- The controller evaluates the most recent 200 durable activities by default
  and returns a bounded agent recency index plus a small log tail. GUI settings
  may narrow that window by Fugue event count or elapsed time. Assigned,
  selected and operator-attention nodes are always retained.
- Snapshot/watch stay metadata-only. Full text remains available exclusively
  through the existing selected-agent private plane.

Acceptance requires controller normalization tests for exact child/source
relationships and bounded activity metadata; UI tests for retention, nested
pool forces, collision, route pulses and camera preservation; Rust boundary
tests for unchanged framing/content rejection; the production frontend build;
and installed-app visual verification.

The phase-1 local security boundary treats the logged-in OS account as trusted;
it is not designed to resist a malicious process already executing as that
user. Path, peer-credential and launchd-PID checks prevent accidental endpoint
substitution and cross-user access, but they are not a cryptographic service
identity. Locally built application bundles may receive an ad-hoc integrity
seal for development; an externally distributed release must first bind
controller identity using a signed service/channel design and use the normal
Developer ID/notarization pipeline.

## Platform seam

The React application and Tauri command surface are shared by every platform.
The transport implementation is selected at compile time:

- macOS uses the current owner-only Fugue Unix socket and managed launchd PID;
- Linux contains the XDG Unix-socket seam but deliberately fails closed until
  the controller's systemd user-service identity can be verified;
- Windows retains the same no-argument command boundary and will use a
  user-scoped named pipe once the controller's Windows service profile exists.

Linux and Windows therefore build the UI shell in phase 1 but report the
controller as unavailable. Shipping them requires their controller service
identity and transport implementation; neither is simulated with an
unauthenticated localhost HTTP server.

## Source influences

The implementation is fresh code. OpenHands Agent Canvas informs the control
centre hierarchy; Vibe Kanban informs Tauri packaging and workspace density;
Temporal UI informs durable-state and attention presentation; OpenCode Desktop
informs provider/session terminology. No AGPL Opcode source is incorporated.

Any future copied MIT or Apache-2.0 source must retain its required notice and
be recorded before merge.

Three.js `0.185.1` and matching `@types/three` are pinned locally for the 3D
topology. The Three.js MIT notice and both self-hosted font OFL notices are
bundled as application resources.

## Acceptance

This phase is complete when:

1. TypeScript normalization and component tests cover healthy, degraded and
   unavailable snapshots.
2. Rust tests cover exact framing, response correlation, frame limits,
   change-wait behavior and sanitized errors.
3. Frontend production build and `cargo test`/`cargo check` pass.
4. A local Tauri development build reads the running controller and renders the
   same headline state plus its validated worker relationships as a topology.
5. Independent review accepts the native bridge and capability boundary before
   a local application bundle is installed. Installer publication, Developer ID
   signing and external distribution remain disabled until the signed
   service/channel identity requirement is resolved.
