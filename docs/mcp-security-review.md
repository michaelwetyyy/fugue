# Fugue Dev MCP independent security review

Review date: 2026-09-12

## Verdict

**Pass for the isolated read-only Fugue Dev MCP boundary, subject to the residual
constraints below.** This review completes the local independent-security-review
gate for the `dev-lab` MCP server. It does not authorize the live Fugue bundle,
Codex/App Server writes, OpenCode delivery, a production controller connection,
or a remote Secure MCP Tunnel/ChatGPT custom-app connection.

The reviewed server is `ui/src-tauri/src/mcp_dev.rs`, enabled only by the
`dev-lab` Cargo feature and the `Fugue Dev` Tauri identity. Its only application
data source is `ui/src-tauri/src/dev_lab.rs`.

## Threat model

The boundary assumes:

- arbitrary HTTP input may reach the loopback listener and is hostile until Host,
  Origin, bearer, protocol, session and method checks pass;
- MCP request bodies, tool names, metadata and JSON structure are hostile even
  after transport authentication;
- other local macOS users are untrusted;
- a process already running as the operator's UID is inside the accepted local-user
  trust boundary and can read or alter user-owned state;
- the live Fugue controller, live OpenCode configuration, Codex App Server,
  repository contents and user prompts are not data sources for this server; and
- remote tunnel/control-plane trust is out of scope until separately provisioned.

## Findings closed by this review

### SR-1 — duplicate JSON object keys were ambiguous

**Severity:** medium. **Status:** fixed.

The HTTP boundary previously parsed request bodies directly into
`serde_json::Value`. Duplicate object names therefore used last-value-wins
semantics. At an authenticated protocol boundary this can create parser
ambiguity between intermediaries or validators and the MCP server, especially
for duplicate `method`, `name`, `arguments` or `_meta` fields.

The server now uses a recursive custom Serde visitor that rejects duplicate
object keys at every depth before JSON-RPC dispatch. Syntax errors remain parse
errors; duplicate-key payloads fail as invalid requests. Adversarial tests cover
both top-level and nested duplicates.

### SR-2 — route rejection preceded transport-origin validation

**Severity:** low / defense in depth. **Status:** fixed.

An alternate path could receive `404` before Host, Origin and bearer validation.
The MCP Streamable HTTP security guidance requires Origin validation on incoming
connections to prevent DNS rebinding. Host, Origin and authorization are now
validated before route or method dispatch. Tests prove an invalid Origin on an
alternate path returns `403` and an unauthenticated alternate path returns
`401`, without exposing route handling first.

Reference: <https://modelcontextprotocol.io/specification/2025-11-25/basic/transports>

## Controls verified

### Build and namespace isolation

- MCP code is compiled only with the `dev-lab` feature.
- Startup verifies the embedded application identifier
  `com.tensorhost.fugue.dev` and product name `Fugue Dev` before the listener is
  created.
- The server refuses a non-loopback bind and the packaged profile uses only
  `127.0.0.1:4197`.
- The MCP module imports `dev_lab` rather than the live cockpit/controller,
  OpenCode or Codex source bridges.

### HTTP and protocol boundary

- Only exact `/mcp` traffic is routed after transport security checks.
- Host is restricted to the exact loopback host/port forms.
- Origin is validated when present; unknown origins fail `403`.
- A fixed-format 256-bit bearer is required before MCP parsing.
- Duplicate HTTP headers and all `Transfer-Encoding` requests are rejected,
  avoiding ambiguous framing; one bounded `Content-Length` is required for
  POST.
- Header/body ingestion has one absolute two-second deadline, a 16 KiB header
  cap and 64 KiB body cap.
- Concurrent connections, sessions and per-session tool calls are bounded.
- Session IDs use 256 bits of OS randomness, have closed visible-ASCII syntax,
  and expire on bounded timers.
- Subsequent requests must carry the negotiated `MCP-Protocol-Version` and exact
  session ID.
- JSON-RPC batches, unsolicited response objects and unadvertised methods fail
  closed.

### Credential storage

- The bearer is stored under
  `~/Library/Application Support/oc-rig-v2-dev/mcp/auth-header`.
- Fugue traverses from an already-open HOME descriptor with fixed child names and
  `openat`/`mkdirat`, `O_NOFOLLOW` and `O_CLOEXEC`.
- Fugue-created directories require owner identity, exact mode `0700`, and no
  extended ACL. System ancestors cannot grant access through an ACL.
- The bearer must be a regular owner-owned non-hardlinked mode-`0600` file with
  no extended ACL.
- The bearer is never included in MCP results or synthetic state.

### Tool authority and data egress

`tools/list` exposes exactly `fugue_dev_status` and `fugue_dev_snapshot`.
Both tools:

- accept only an empty object;
- are annotated read-only, non-destructive, idempotent and closed-world;
- forbid MCP task execution;
- have no generic method, path, query, repository, file, thread, turn or message
  argument; and
- return only synthetic in-process state.

Annotations are treated as descriptive hints, not as the security boundary. The
actual enforcement is the closed method/tool allowlist and compile-time data
isolation.

Reference: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>

The snapshot tool additionally verifies the synthetic provenance marker, null
live event sequence, exact thirteen-slot topology, disabled integration,
metadata-only recent turns, and disabled callback adapter before serializing the
snapshot.

## Resource-exhaustion posture

The listener admits at most 16 concurrent connections. A connection must deliver
its headers and declared body within one absolute two-second deadline. At most 32
sessions exist at once; sessions that never complete initialization expire after
30 seconds and cannot renew that deadline. Ready sessions expire after ten
minutes of inactivity. Tool calls are capped at 60 per minute per session.
Responses are capped at 64 KiB.

These are availability limits, not authorization. A process already running as
the same macOS UID is considered trusted by the local-user profile and can still
consume local resources or read the bearer.

## Dependency and implementation gates

The MCP implementation adds no HTTP framework, shell, filesystem browser,
opener or outbound-network client. Direct Rust dependencies are exact-pinned in
`Cargo.toml`; the extra MCP-specific randomness dependency is optional and gated
by `dev-lab`.

Review gates and recorded results:

1. `cargo fmt --check` — pass.
2. `cargo clippy --features dev-lab --all-targets -- -D warnings` — pass.
3. `cargo test --features dev-lab` — pass: all 26 dev-lab library tests pass;
   the Codex-source contract adds 11 passes with one live-App-Server test
   intentionally ignored.
4. `cargo check --features dev-lab` and ordinary `cargo check` — pass.
5. RustSec audit of the exact `Cargo.lock` with `cargo-audit 0.22.2` — pass for
   vulnerability advisories. The audit loaded 1,243 advisories and scanned 431
   locked crate dependencies with no vulnerability finding. It reported seven
   allowed warnings: five unmaintained `unic-*` crates, unmaintained
   `proc-macro-error 1.0.4`, and the `glib 0.18.5` iterator-soundness advisory.
   `glib` and `proc-macro-error` are absent from the `aarch64-apple-darwin`
   dependency graph; the `unic-*` warnings are transitive through
   `urlpattern -> tauri-utils` and are maintenance warnings rather than
   vulnerability advisories. The reviewed tree already pins Tauri 2.11.5.
6. Packaged `Fugue Dev.app` code-sign verification, launch probe and local MCP
   lifecycle probe — pass. The rebuilt signed app negotiated the exact protocol,
   exposed exactly the two reviewed tools, returned only the validated synthetic
   snapshot, rejected recursive duplicate JSON keys, applied Host/Origin/bearer
   checks before alternate-path routing, and released the loopback listener after
   process termination. The probe read the bearer only from its private file and
   did not emit it.

## Residual constraints and stop lines

- The bearer is long-lived local state. If compromise is suspected, stop Fugue
  Dev and any tunnel client, remove the credential, then allow Fugue Dev to
  create a new one before reconfiguring the tunnel. Automatic rotation is not
  part of this phase.
- A same-UID compromise is outside the protection offered by this local-user
  profile. This is an explicit accepted limitation, not a sandbox claim.
- Native macOS Dock/Apple-event Quit remains a desktop lifecycle issue. Fugue's
  application-menu Quit / `Cmd-Q` path is separately wired to
  `AppHandle::exit(0)` so an explicit in-app quit does not depend on that native
  event. The remaining Dock/Apple-event limitation does not grant MCP authority.
- Secure MCP Tunnel and ChatGPT custom-app provisioning remain separate. This
  review does not create a tunnel, change the existing Mac Bash tunnel, or prove
  OpenAI control-plane authentication.
- Any new MCP tool with write, message, filesystem, repository, controller,
  OpenCode, Codex/App Server or arbitrary-query authority requires a new threat
  model and review. It must not inherit this read-only approval.
