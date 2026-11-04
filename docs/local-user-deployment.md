# macOS local-user deployment profile

This profile is an explicit risk tradeoff for a Mac where the operator's login is
the only trusted user account. It does not replace or relax the dedicated
service profile: the dedicated profile still requires a separate service UID,
client group, root-owned bootstrap artifacts, and its `0710`/`0620` boundary.

The local-user profile cannot protect rigd from another process already running
as the operator. That process can change user-owned code, launch agents, state, or
hash pins. The profile instead provides a deterministic, owner-only boundary
against other local accounts and catches accidental replacement, corruption,
permission drift, symlinks, and unmanaged state before a managed action.

## Fixed layout

The default deployment root is
`~/Library/Application Support/oc-rig-v2/`. It is separate from every Rig v1
path and the tooling neither reads nor changes Rig v1.

| Purpose | Boundary |
|---|---|
| Deployment, runtime, logs, socket directories | user-owned `0700` |
| Versioned release directory | user-owned `0500` |
| Wheel, release manifest, release pin, launcher | user-owned `0400` |
| Deployment pointer, database, lock, logs | user-owned `0600` |
| OpenCode auth, topology, and trust generations | `config/opencode/<config-id>/`, files user-owned `0600` |
| Live Unix socket | user-owned `0600` |
| Daemon `HOME` | `runtime/home/`, user-owned `0700`, never the login home |
| LaunchAgent | `~/Library/LaunchAgents/com.tensorhost.oc-rig-v2.plist`, user-owned `0600` |

Each release ID contains the package version and wheel hash prefix. The full
wheel, manifest, member, and Python-interpreter hashes are checked before a
release is accepted or started. The selected interpreter's isolated `sys.path`,
prefixes, and complete controlled ancestry identities are pinned as well. Every
runtime ancestor must be root- or user-owned and not group/world writable;
write-granting ACLs and ambient `site-packages` are rejected. A normal Homebrew
runtime below a group-writable Cellar therefore fails closed. Supply an explicit
reviewed Python 3.11+ runtime with `--python`.

Long-lived macOS pins identify each filesystem by its native APFS volume UUID,
not `st_dev`: macOS may renumber `st_dev` across an ordinary reboot without any
object replacement. Inode, owner, mode, link count, selected directory and file
ctime, ACL digest, size, and content hashes remain fail-closed as applicable.
`st_dev` is still compared with inode while a single validation is in progress,
so a pathname or descriptor race cannot be mistaken for reboot renumbering.
The sealed macOS root volume is the sole stopped-upgrade exception: its UUID
may rotate after an OS update only while `/` remains inode 2, root-owned mode
`0755`, and every other runtime fact and non-root volume UUID remains exact.
The newly built immutable release then pins the current root UUID.

`deployment-state.json` holds `current`, `previous`, and an optional OpenCode
configuration identity; replacing this one
regular file atomically switches releases. Rollback additionally requires the
operator to name the expected current and exact target release, so repeating the
same rollback is idempotent only while `current` is the target and `previous`
is that exact expected-current release; a mismatched retry fails rather than
toggling releases. Symlinks are never used as release pointers.

The LaunchAgent has `RunAtLoad` and `KeepAlive` disabled. Installing or
bootstrapping the agent does not start rigd. It invokes the pinned interpreter
with `-I -S -B`, validates the generated launcher and runtime pins, clears the
ambient environment, and sets `HOME` to the dedicated owner-only directory
inside v2. Only a minimal `PATH`, locale, and `PYTHONNOUSERSITE` remain. It does
not inherit credentials, the login `HOME`, Rig v1 paths, OpenCode settings, or
tmux configuration. No install or configuration command uses the network or
`sudo`. The daemon remains on `DisabledAdapter` until the explicit state-selected
OpenCode generation below is installed.

OpenCode configuration is a separate stopped-daemon action. It accepts only an
explicit loopback HTTP endpoint, an explicit raw Basic-password file, and
explicit private topology and trust JSON files. The raw password is never
printed. All three managed JSON files are published together in a private
generation directory; their SHA-256, volume UUID, inode, and size are pinned in
the atomic deployment-state pointer. The generated launcher passes those exact
paths and the selected configuration identity to `rigd-local-user`; rigd does
not inspect `HOME`, environment variables, or ambient OpenCode files. Session
IDs can be replaced by configuring a new topology while rigd is stopped.

Before `kickstart`, signal, or `bootout`, the manager authenticates launchd's
exact plist path, program, arguments, label, and managed plist bytes. A foreign
job occupying the label or an ambiguous launchctl inspection error is left
untouched. A start returns only after authenticated socket health; failed
readiness triggers authenticated termination and verifies both the process and
socket are gone. Initial installation inspects the label and refuses an
unmanaged existing plist before publishing any v2 state, then repeats that
inspection immediately before launch-agent configuration. The plist is created
relative to a pinned directory descriptor with `O_EXCL` and `O_NOFOLLOW`; an
intervening foreign plist is never replaced. If bootstrap fails, cleanup removes
only attempt-created artifacts whose inode identities still match; a foreign
replacement or job is not removed or signalled.

## Commands

Run from a reviewed Fugue source checkout. Previewing an install still
builds and verifies the wheel in a temporary directory, but leaves the target
and launchd unchanged:

```bash
PYTHONPATH=src python3 tools/user_deployment.py --python /reviewed/python3 --dry-run install --source-root .
PYTHONPATH=src python3 tools/user_deployment.py --python /reviewed/python3 install --source-root .
```

Preview and install the live loopback configuration only after reviewing all
four input paths:

```bash
PYTHONPATH=src python3 tools/user_deployment.py --python /reviewed/python3 --dry-run \
  configure-opencode --endpoint http://127.0.0.1:4096 \
  --basic-username opencode --basic-password-file /private/path/opencode.password \
  --topology-file /private/path/opencode-topology.json \
  --trust-file /private/path/opencode-trust.json
PYTHONPATH=src python3 tools/user_deployment.py --python /reviewed/python3 \
  configure-opencode --endpoint http://127.0.0.1:4096 \
  --basic-username opencode --basic-password-file /private/path/opencode.password \
  --topology-file /private/path/opencode-topology.json \
  --trust-file /private/path/opencode-trust.json
```

With OpenCode configured and the deployment stopped, explicitly select the
local completion callback. Use the resolved canonical Codex app executable,
not a symlink:

```bash
PYTHONPATH=src python3 tools/user_deployment.py --python /reviewed/python3 \
  configure-codex-callback \
  --executable /Applications/ChatGPT.app/Contents/Resources/codex \
  --user-home /Users/USERNAME --codex-home /Users/USERNAME/.codex
```

The executable is pinned by volume UUID, inode, owner, mode, size, and content
hash. `status` exposes only whether this callback is configured; it does not
expose the paths or thread routes. A later executable replacement fails closed
on `status`, `start`, and ordinary configuration. Refresh only that stale pin
with the separate explicit stopped-only action:

```bash
PYTHONPATH=src python3 tools/user_deployment.py --python /reviewed/python3 \
  refresh-codex-callback \
  --executable /Applications/ChatGPT.app/Contents/Resources/codex \
  --terminal-ownership "$HOME/.config/opencode/.rig-v2-lifecycle/ownership.json" \
  --tmux /reviewed/canonical/tmux --session oc-rig-v2
```

The refresh validates the entire existing deployment, release, and OpenCode
configuration while allowing only the old callback executable pin to be stale.
It requires an unloaded/stopped controller, empty socket boundary, free daemon
lock, exact canonical stopped terminal ownership, no tmux session, and no
listener at the configured backend endpoint. The caller-supplied executable is
canonical and non-symlinked, and its volume UUID, inode, owner, mode, size, and
hash are captured with race fences. Publication atomically replaces only the
callback executable path/pin; all other state is preserved. `--dry-run` performs
the same validation and writes nothing; unlike ordinary simulated actions, its
controller check executes the real read-only `launchctl print` inspection.

Install, OpenCode/Codex configuration, callback refresh, start, stop, rollback,
and uninstall share one exclusive lock on the controlled deployment parent
directory. The lock spans initial validation, state publication, postvalidation,
and any rollback, preventing refresh-refresh and refresh-start overlap. Callback
refresh also uses compare-and-swap rollback: prior state is restored only while
the current bytes still exactly equal that refresh's own replacement. A changed
state is preserved and reported instead of being overwritten by stale rollback.
Terminal finalization takes the same lock before its final authenticated
controller check and holds it through stop, exact unloaded/waiting/not-running recovery
status, backend process-group cleanup, and canonical stopped publication. It
uses the internal unlocked stop primitive while holding that outer lock, so a
concurrent start cannot enter between controller termination and ownership
publication.
Cleanup resumption acquires that same operation lock before controller/backend
adoption and retains it until cleanup and stopped publication (or handoff/fail
closed). It clears retained controller ownership only for an exact allowed
stopped shape, adopts only the exact original running PID, and leaves the
original ownership bytes unchanged for transitional, malformed, or changed-PID
status. Thus a timed-out stop cannot be converted into an unauthenticated retry
or race a new start.
macOS `launchctl print` may report `state = not running`; the bounded parser
requires one unique complete top-level job state line at exact one-tab
indentation and normalizes only that exact raw value
to detail `not`. Missing/duplicate lines, bare `not`, `not …` variants, and
other multi-token values are malformed. Nested coalition/resource/jetsam state
fields at two-or-more-tab indentation are ignored; unindented, space-indented,
mixed-indentation, or duplicate top-level state fields fail closed. Recovery accepts loaded stopped
state only with `running: false`, `pid: null`, and detail exactly `waiting` or
`not`; prefix-like, unknown, and other loaded details remain fail-closed.
Because launchd may briefly expose a transitional value after stop, finalization
polls locally for at most five seconds while holding the shared operation lock.
It may wait through the exact original running PID or structurally valid
nonrunning/`pid: null` transitional details, but publishes only on an exact
allowed stopped shape. A changed live PID, malformed status, or inspection
failure aborts immediately; persistent transition times out with ownership
retained and concurrent start still blocked until the finalizer exits.

`status` reports only configured/unconfigured, the non-secret loopback endpoint,
and the configuration identity. Missing files, permission drift, partial
generations, state substitution, or hash/inode changes prevent a live start.

The first install refuses any nonempty unmanaged v2 root. It constructs and
validates the runtime, release, launcher, and state in a private sibling stage,
then publishes those entries inside the retained v2 root with the state file as
the final commit marker. A caller-supplied empty root keeps its exact directory
identity even if publication fails. A malformed first attempt is removed
completely (or leaves that caller root empty), so a clean retry works. A later
install is an upgrade only when the complete existing managed layout validates
and rigd is stopped. Before the first entry is published, an fsynced sibling
attempt manifest records the exact root, staging, and complete artifact inode
trees. Its exclusive write handles interruptions and short writes, fsyncs, then
seeks and verifies the exact bytes through the same descriptor before any entry
moves. After a crash, every entry must exist in exactly one recorded location
and the exact stage must remain until the final state marker is published.
Missing, duplicate, changed, or unknown content is preserved and stops recovery.
Only a complete committed root may outlive its emptied stage. This makes a
SIGKILL-interrupted initial publication retryable without broad staging-name
cleanup. Upgrades stage a new immutable release, then atomically select it while
retaining the former current release as `previous`.

The stable-volume repair uses release-pin v3, OpenCode-pin v2, and Codex-callback
pin v2. Those formats are deliberately incompatible with their `st_dev`-pinned
predecessors. Never edit an existing release pin to migrate it: build and review
a newly hashed immutable release with the new tooling, and recreate the optional
OpenCode and Codex callback selections so deployment state contains the new pin
formats before launch.

Lifecycle operations are explicit:

```bash
PYTHONPATH=src python3 tools/user_deployment.py --python /reviewed/python3 status
PYTHONPATH=src python3 tools/user_deployment.py --python /reviewed/python3 start
PYTHONPATH=src python3 tools/user_deployment.py --python /reviewed/python3 stop
PYTHONPATH=src python3 tools/user_deployment.py --python /reviewed/python3 rollback --expected-current VERSION-HASH --target PREVIOUS-VERSION-HASH
```

`start` refuses a running job or leftover socket. `rollback` refuses to run
while rigd is active and selects only the explicitly bound target without
starting it. All lifecycle commands also accept the global `--dry-run` option.

The desktop app invokes the installed terminal lifecycle with `--mode app`.
That mode performs the same completed-cutover, backend, controller and ownership
checks as `open`, creates the same detached managed session, and returns without
attaching an interactive terminal. This keeps the graphical app as the only
visible surface while durable work continues in the background.

## Terminal lifecycle

After the reviewed release is installed, its immutable wheel supplies the
terminal lifecycle. The managed `launcher.py` verifies the selected wheel,
manifest, interpreter, and runtime pins before importing
`oc_rig.terminal_cli`; the user-facing command never imports a mutable source
checkout.

```bash
"$PINNED_PYTHON" -I -S -B "$ROOT/launcher.py" "$ROOT" --terminal \
  --home "$HOME" --plist "$HOME/Library/LaunchAgents/com.tensorhost.oc-rig-v2.plist" \
  --opencode /reviewed/opencode --launchctl /bin/launchctl --tmux /reviewed/tmux \
  --backend-directory "$HOME/.config/opencode/.rig-v2-automated-backend" \
  --backend-work-directory "$HOME/Library/Application Support/oc-rig-v2-backend-work" \
  --ownership "$HOME/.config/opencode/.rig-v2-lifecycle/ownership.json" \
  --cutover-existing \
  --legacy-backend-label com.tensorhost.opencode.backend.4096 \
  --legacy-backend-program "$HOME/.config/opencode/bin/oc-backend.sh"
```

The explicit direct-cutover flags authenticate the exact old backend launchd
program and arguments, then require an exact quiescent snapshot from the
authenticated running v2 controller before removing only that job. Active,
degraded, unavailable, or stopped controller state aborts with the legacy
backend untouched. The running v2 controller is adopted by exact PID.
The command is idempotent across a crash because a later invocation first takes
the exclusive lifecycle lock, recovers a complete pending publication, and
adopts only matching recorded controller/backend identities.

After a prior v2 direct cutover has completed, a fresh immutable release must
not infer success merely because the legacy launchd job is absent. Migration is
explicit and requires an operator-pinned hash of the exact archived live
ownership record plus the retained, immutable source deployment. The source
release pin and artifact hashes, config hashes/inodes, quiescent database
snapshot, controller PID, legacy PID, release/config IDs, and the current
destination release/config are cross-checked before either backend or
controller can start. The retained database must be fully checkpointed: any
SQLite WAL, shared-memory, or rollback-journal sidecar makes migration fail
closed rather than ignoring committed sidecar state.

## Codex review and proposal routes

The same managed launcher exposes a narrow Codex route only after verifying the
selected release, wheel, manifest, interpreter, and runtime pins. Its grammar
allows controller reads, exact result reads, PUBLIC file-capsule reviews, and
capsule-bound no-tool task proposals. It cannot accept sensitive
classifications, risk overrides, transport mutations, or caller-selected
socket and identity parameters. Task objectives are bounded and the fixed
worker cannot write files or run commands; Codex remains the only checkout
writer and final consolidator.

```bash
CODEX_THREAD_ID=LOWERCASE-CODEX-UUID \
  "$PINNED_PYTHON" -I -S -B "$ROOT/launcher.py" "$ROOT" --terminal \
  --codex-route "$CODEX_THREAD_ID" \
  review tensorhost /absolute/repository \
  --scope src/review.py --profile correctness \
  --idempotency-id stable-review-id
```

```bash
CODEX_THREAD_ID=LOWERCASE-CODEX-UUID \
  ~/.config/opencode/bin/oc-route task control /absolute/repository \
  --scope src/app.tsx --scope src/settings.tsx \
  --objective 'Return a concrete bounded implementation proposal.' \
  --lifecycle persistent --idempotency-id stable-task-id \
  --reservation-attempt 1
```

For a large PUBLIC file, the patch route discloses only one caller-selected
inclusive line window and returns an exact brokered edit:

```bash
CODEX_THREAD_ID=LOWERCASE-CODEX-UUID \
  ~/.config/opencode/bin/oc-route patch personal /absolute/repository \
  --scope src/large.tsx --lines 220:280 \
  --objective 'Edit the bounded renderer.' \
  --lifecycle disposable --idempotency-id stable-patch-id \
  --reservation-attempt 1
```

The full preimage remains in private controller authority and never enters the
worker prompt. Any change anywhere in that file invalidates the patch; matching
only the disclosed lines is insufficient. The durable result contains the
range and before/after hashes but no source or replacement text.

Supply the reviewed source and evidence bindings on the first cold open:

```bash
"$PINNED_PYTHON" -I -S -B "$ROOT/launcher.py" "$ROOT" --terminal \
  --home "$HOME" --plist "$HOME/Library/LaunchAgents/com.tensorhost.oc-rig-v2.plist" \
  --opencode /reviewed/opencode --launchctl /bin/launchctl --tmux /reviewed/tmux \
  --backend-directory "$HOME/.config/opencode/.rig-v2-automated-backend" \
  --backend-work-directory "$HOME/Library/Application Support/oc-rig-v2-backend-work" \
  --ownership "$HOME/.config/opencode/.rig-v2-lifecycle/ownership.json" \
  --cutover-existing \
  --legacy-backend-label com.tensorhost.opencode.backend.4096 \
  --legacy-backend-program "$HOME/.config/opencode/bin/oc-backend.sh" \
  --completed-cutover-evidence /reviewed/archive/prior-ownership.json \
  --completed-cutover-evidence-sha256 REVIEWED_64_HEX_SHA256 \
  --completed-cutover-source /reviewed/retained-prior-deployment \
  --completed-cutover-source-release REVIEWED_PRIOR_RELEASE_ID \
  --completed-cutover-source-config REVIEWED_PRIOR_CONFIG_ID \
  --completed-cutover-controller-pid REVIEWED_CONTROLLER_PID \
  --completed-cutover-legacy-pid REVIEWED_LEGACY_PID
```

The destination must already contain an exact stopped ownership record and no
live owned backend, controller, or matching tmux session. Adoption atomically
creates a destination-local, mode-`0600`, one-time receipt and binds it into
ownership before start. Receipts are keyed by exact destination release and
config; reviewed immutable upgrades create a separate receipt and leave all
prior receipts unchanged, while reuse or alteration for the same destination
fails closed. Subsequent opens require an exact zero-resource,
zero-tmux stopped record and the same receipt, source, and destination bindings.
An absent, invented, altered, active, stale, or replayed proof fails before
backend/controller start; the legacy job is never recreated or re-enabled.

The attended terminal is a single read-only Fugue cockpit. OpenCode worker
sessions remain headless and appear through the controller projection rather
than occupying five embedded TUI panes. This keeps the operational fallback
small while preserving the pinned topology, routing and lifecycle boundaries.
It does not run the Rig v1 watchdog or mutating hub. The cockpit starts in a
compact human view: lane names, agent names, simple state symbols, active work
links, and only nonempty queue or attention sections. Projection warnings and
unavailable sections remain visible. Session identifiers, transport/completion/
recovery internals, refresh metadata, capacity, and unavailable token/turn
metadata stay out of the compact view. For the complete normalized diagnostic
projection, including every hidden field, run:

```bash
rigctl [connection options] cockpit --details
```

`rigctl [connection options] cockpit --format json` remains the compact
machine-readable equivalent of the same complete projection.

Final detach runs a local,
no-model/no-token finalizer. If the projection proves an exact empty queue,
eleven clear slots, and no attention state, it immediately stops only the
invocation-owned authenticated controller and exact backend process group—no
quiescent grace period. When work remains, the finalizer checks locally every
two seconds until quiescent, bounded by six hours by default. At the bound or
on unavailable state it retains resources and the durable ownership record
unchanged, fail-closed for the next invocation. Finalizer retries resume
shutdown from that exact record without
starting replacement resources. If the controller exits before backend cleanup,
the recorded backend process identity remains durable until that exact process
group terminates; a failed retry cannot replace it with an empty stopped record.
Process inspection distinguishes an exact match from conclusive absence. PID
reuse, ambiguous `ps` output, or an inspection error preserves the original
ownership record and stops neither the controller nor the observed process.
On macOS, a zombie/dead state is also conclusive only when `ps` still matches
the recorded PID, start time, and process group; its command may already be
gone. A different start time or process group remains a fail-closed PID reuse.
The terminated leader alone is not sufficient: cleanup inspects the exact
recorded process group using a fixed native `ps -axo` process-table snapshot and
exact numeric PGID filtering. Output size, line count/length, numeric fields,
states, and duplicate target PIDs are bounded and validated. Two anchored live
snapshots are required before signalling that group at most once, and cleanup retains
ownership until every same-PGID member is absent or zombie/dead. A live child,
leader reuse, malformed group listing, or group-inspection error prevents
stopped publication.
If live same-PGID members are visible but the exact recorded leader/start anchor
is absent, the group is unanchored: cleanup sends no signal and preserves the
ownership record unchanged. Only a group already signalled while anchored may
later be observed without its leader, and that observation is wait-only until
the group becomes wholly terminated or empty.
The process table is read as raw pipe chunks and parsed line-by-line while `ps`
is running; stdout, stderr, partial-line, line-count, and deadline caps are
enforced before bounded decoding. Hitting a cap terminates and reaps the probe
immediately. Nonzero exit, any stderr, or a truncated final line fails closed.
After the exact anchored group has been signalled, a transient classifier error,
mismatch, or missing-leader/live-child observation is wait-only: ownership is
retained, no second signal is sent, and only a later empty or wholly terminated
snapshot permits stopped publication. Persistent uncertainty times out closed.
Terminal-loss signals deferred through the durable controller-stopped marker do
not abort exact backend cleanup; cleanup continues through canonical stopped
publication before tmux removal. Any finalizer exception or timeout is also
published locally as mode-`0600` `finalizer-error.json` beside ownership. That
record contains only fixed allowlisted error category/code values and a timestamp, never exception
text, command output, paths, configuration, or credentials.
Fixed lifecycle subcodes distinguish snapshot validation, signal-context,
controller status/identity, backend identity/group inspection, ownership, and
timeout branches. Snapshot normalization failures are durably retained as a
lifecycle reason, and signal deferral outside the process main thread becomes a
fixed lifecycle error instead of an unclassified runtime exception.
Signal deferral records a pending signal only when its protected body succeeds;
an ownership, controller, or backend security exception from the body is always
re-raised unchanged even if a terminal signal arrived concurrently.

A second invocation first checks for the exact tmux session ID recorded by the
lifecycle. A match attaches without touching lifecycle or backend state; a
mismatch refuses. The deferred finalizer checks attachments before every
quiescence attempt and again immediately before stop, handing durable ownership
back without stopping anything when a client reattaches.

A stop wrapper must delegate unconditionally to the pinned terminal launcher
with `--mode stop`; it must not decide that the rig is stopped from controller,
backend, or tmux probes. Stop mode validates and removes only the matching tmux
session, then consults durable ownership. A pending record is resumed even when
both processes are already absent, while an exact canonical `stopped` record is
idempotent. `phase: stopped` alone is insufficient: every allowed field and
type must be canonical, all backend/controller ownership and identities must be
empty, and tmux nonce/session fields must be null. Any inconsistency fails
without killing tmux, signalling a process, or attempting cleanup. This makes
repeated stop commands complete an interruption between
backend termination and stopped-state publication.

Uninstalling removes only the user LaunchAgent and retains releases and state:

```bash
PYTHONPATH=src python3 tools/user_deployment.py --python /reviewed/python3 uninstall
```

Deleting the validated v2 deployment requires both explicit destructive flags.
It still never touches Rig v1:

```bash
PYTHONPATH=src python3 tools/user_deployment.py --python /reviewed/python3 uninstall --purge --confirm-purge
```

Use `--root`, `--plist`, and `--launchctl` only for an explicitly reviewed
alternative layout or an isolated test. `--python` is always required and must
name the same reviewed controlled runtime for every lifecycle command. A
local-user client must explicitly select `rigctl --identity-profile local-user`;
omission remains dedicated-service and requires `--service-uid` plus
`--client-gid`. Cross-profile socket modes are rejected rather than downgraded.
After `start`, a non-secret live check is:

```bash
PYTHONPATH=src python3 -m oc_rig.cli \
  --socket "$HOME/Library/Application Support/oc-rig-v2/runtime/socket-boundary/socket/rig.sock" \
  --approved-root "$HOME/Library/Application Support/oc-rig-v2/runtime/socket-boundary" \
  --identity-profile local-user health
```
