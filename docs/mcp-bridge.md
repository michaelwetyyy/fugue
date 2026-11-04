# Fugue Dev MCP bridge

## Status

This note is the current authority for the isolated Fugue Dev MCP boundary.
The first read-only MCP phase is implemented behind the `dev-lab` Tauri feature
in `ui/src-tauri/src/mcp_dev.rs`. It starts with Fugue Dev, binds only
`127.0.0.1:4197`, serves only `/mcp`, and reads only the in-process synthetic
state from `dev_lab`. The live controller, OpenCode backend, Codex App Server,
and all message-delivery paths remain excluded from this build.

This phase is deliberately read-only. It exposes only the fixed synthetic
status and snapshot described below. A tool that sends, steers, starts, resumes,
injects, submits work, cancels work, or otherwise changes a Codex or Fugue task
is outside this phase and remains disabled. The local server has not yet been
registered as a ChatGPT custom app or attached to a Secure MCP Tunnel.

## Fixed isolation identity

The MCP implementation must obtain its identity from the `dev-lab` profile and
must fail closed if any value differs:

| Property | Required value |
| --- | --- |
| Tauri feature | `dev-lab` |
| MCP server name | `fugue-dev` |
| Application identifier | `com.tensorhost.fugue.dev` |
| Launchd label | `com.tensorhost.oc-rig-v2.dev` |
| Development port | `4197` |
| Callback mode | `shadow` |
| Backend integration | disabled |
| Codex delivery | disabled |

Before the MCP listener is bound, Fugue generates the exact Tauri application
context and verifies that its embedded identifier is `com.tensorhost.fugue.dev`
and its product name is `Fugue Dev`. Enabling the Cargo feature without the dev
Tauri configuration therefore fails closed before port `4197` can open.

The implementation must not import a live socket path, runtime directory,
OpenCode configuration, callback route, credential, task identifier, or
controller result. Its only data source is the in-process synthetic state in
`ui/src-tauri/src/dev_lab.rs`.

## Protocol contract

The initial server targets the stable MCP revision `2025-11-25`. It uses
JSON-RPC 2.0 and implements the required lifecycle:

1. Accept `initialize` as the first request and return the selected protocol
   version, server identity `fugue-dev`, package version, and only the `tools`
   server capability.
2. Accept `notifications/initialized` before normal tool traffic.
3. Accept `ping`, `tools/list`, and `tools/call` after initialization.
4. Reject every other request with the standard method-not-found response.
5. Return no response for valid notifications and reject JSON-RPC batches.

The capability declaration must not advertise resources, prompts, logging,
sampling, roots, elicitation, tasks, subscriptions, or list-change
notifications. Requests are capped at 64 KiB before parsing. Responses are
serialized in memory, and any serialized response over 64 KiB is replaced with a
fixed bounded internal-error response before it is written. Unknown fields in the
two tool argument objects are rejected.

The selected transport is Streamable HTTP. It binds only to `127.0.0.1:4197`,
serves only `/mcp`, validates the exact loopback `Host`, validates `Origin` when
present, and requires an owner-controlled bearer credential before parsing MCP
traffic. It implements the session and protocol-version headers required by the
selected revision. Initialization negotiates to the server's single supported
`2025-11-25` revision rather than requiring the client to request that revision
exactly; subsequent requests must echo the negotiated revision. Standard MCP
`params._meta` objects are accepted on lifecycle/read requests while unknown
parameters remain rejected. Sessions awaiting `notifications/initialized` have
a non-renewable 30-second admission deadline; ordinary ready sessions expire
after ten minutes without activity. GET is rejected with `405`; this phase has
no server-initiated SSE stream. Header and body ingestion share one absolute
two-second wall-clock deadline, so pre-authentication trickle traffic cannot renew
a connection slot indefinitely. Requests use JSON responses, valid notifications
return `202` without a body, and unsolicited JSON-RPC response objects are rejected
at the HTTP boundary with `400`.

Loopback binding alone is not authentication. Fugue Dev creates a 256-bit random
bearer value under `~/Library/Application Support/oc-rig-v2-dev/mcp/auth-header`.
The `mcp` directory is owner-controlled mode `0700`; the credential is a regular,
non-hardlinked mode-`0600` file. Fugue opens `HOME` once with `O_NOFOLLOW`, then
retains each directory descriptor while traversing `Library`, `Application
Support`, `oc-rig-v2-dev`, `mcp`, and finally `auth-header` with `openat`/`mkdirat`.
No checked ancestor is re-resolved by pathname before the bearer is opened. Every
directory must be owned by the current user and non-writable by group or world;
the two Fugue-created directories additionally require exact mode `0700`. On
macOS, descriptor-bound ACL inspection rejects every access-granting ancestor
ACL. System-managed ancestors may retain deny-only ACLs such as the standard
`everyone deny delete` entry, while the Fugue-created directories and credential
require no extended ACL at all. The bearer is loaded once into the process, never
returned by an MCP tool, and never written to logs or synthetic state. Secure MCP
Tunnel can inject this header from a file-backed secret when the tunnel phase is
enabled, without copying the value into YAML.

References:

- [MCP lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)
- [MCP transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [MCP tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)

## Read-only tools

`tools/list` returns exactly these tools in this order. Each tool has an empty
object input schema with `additionalProperties: false`, task support forbidden,
and read-only, non-destructive, idempotent, closed-world annotations.

### `fugue_dev_status`

Returns a small structured object containing:

- MCP name `fugue-dev` and protocol revision;
- application identifier, launchd label, and development port;
- `synthetic: true`;
- callback mode `shadow`;
- backend, OpenCode, live controller, Codex App Server, and message delivery all
  reported as disabled; and
- snapshot source `dev_lab`.

### `fugue_dev_snapshot`

Returns the existing bounded synthetic snapshot from `dev_lab::snapshot()`.
Before returning it, the bridge verifies the expected synthetic migration
marker, null event sequence, `synthetic-no-provenance` digest, thirteen-slot
topology, disabled integration, metadata-only recent turns, and no live
callback adapter. A failed invariant produces a tool error and no snapshot.

Both tools return the object as `structuredContent` and, for compatibility, a
compact JSON serialization in one text content block. Neither tool accepts a
repository, file, task, thread, turn, session, destination, query, cursor, or
free-form text argument.

## Codex and message boundary

MCP discovery does not authorize Fugue to write to Codex. Codex App Server is a
separate protocol and remains the authority for authentication, conversation
history, turn state, delivery admission, and streamed commit evidence.

Any future message design needs a separately reviewed capability with all of
these properties before code is enabled:

- an authenticated App Server connection initialized once per connection;
- an exact destination thread ID supplied by durable private authority, never
  inferred from pool membership, recency, visibility, or an idle task;
- `thread/read` or the equivalent authoritative state read before delivery;
- `turn/steer` only for the exact active turn and with its matching
  `expectedTurnId`;
- an explicit, durable route and `turn/start` path when no compatible turn is
  active;
- accepted, queued, committed, failed, and delivery-unknown states kept
  distinct; and
- no blind retry after an uncertain outcome.

The read-only MCP server must not contain dormant message methods, generic
JSON-RPC forwarding, arbitrary App Server method names, or a configurable
destination. Adding those later requires a new threat model and acceptance
phase, not an extension of the status/snapshot tool allowlist.

Reference: [Codex App Server](https://learn.chatgpt.com/docs/app-server).

## Implementation and verification gates

The Rust toolchain gate is now available (`rustc`/`cargo` 1.98.1 in the current
development environment). The server uses the Rust standard library for the HTTP
boundary and adds only an optional `dev-lab`-gated direct pin to the already-locked
`getrandom 0.3.4` for cryptographic bearer and session identifiers. It adds no web
framework, shell, filesystem browser, opener, or outbound-network client
dependency, and the ordinary production feature graph does not enable the MCP
dependency.

The implemented phase currently passes these local gates:

1. `cargo fmt --check`, `cargo test --features dev-lab mcp_dev`, and `cargo check
   --features dev-lab`; the ordinary non-`dev-lab` `cargo check` also remains
   clean.
2. Protocol tests cover application-identity admission, initialization order,
   the non-renewable initialization deadline, server-side version negotiation,
   standard `_meta` compatibility, ping, deterministic tool listing,
   empty-argument enforcement, unknown methods, batch rejection, recursive
   duplicate-JSON-key rejection, and structured/text tool results.
3. Transport tests cover refusal of non-loopback binding, transport Host/Origin
   and bearer checks before route dispatch, exact `/mcp` routing,
   alternate-path rejection, bearer authentication, invalid Host/Origin
   rejection, session ownership, protocol-version headers, request/session
   limits, connection saturation with `503`, per-session tool rate limiting,
   concurrent clients, listener closure on drop, and port-conflict failure.
4. Credential tests cover owner-only creation, stable reuse, exact `0600` mode,
   actual hardlink rejection, symlinked-ancestor rejection, deny-only ancestor
   ACL acceptance, access-granting ancestor ACL rejection, private-leaf ACL
   rejection, and permission tamper failure.
5. Both tools are exercised through the HTTP MCP lifecycle and expose only
   synthetic `dev_lab` data while live modules are compile-time excluded.
6. Strict Clippy passes for all dev-lab targets, and a RustSec audit of the exact
   lockfile reports no vulnerability advisories. The remaining advisory output
   is limited to transitive maintenance warnings plus a non-macOS GTK/GLib
   soundness warning documented in the independent security review.

The packaged `Fugue Dev.app` has now been exercised through the complete local
HTTP MCP lifecycle: the signed bundle bound only `127.0.0.1:4197`, created/reused
the private credential, negotiated protocol `2025-11-25`, advertised exactly the
two read-only/task-forbidden tools, and returned only validated synthetic data. A
process-termination probe also confirmed that termination closes the listener.
No credential value was emitted by those packaged probes. macOS Apple-event/Cocoa
`quit` requests currently remain open as a separate desktop-lifecycle issue and
are not treated as MCP delivery authority.

### Validated Secure MCP Tunnel profile shape

The local tunnel-client doctor accepts the following plain/non-OAuth HTTP profile
shape when Fugue Dev is listening. Placeholder values must be replaced with a
separately provisioned Fugue tunnel ID and a fresh runtime control-plane key file.
The MCP bearer remains file-backed and is not copied into YAML.

```yaml
config_version: 1
control_plane:
  base_url: "https://api.openai.com"
  tunnel_id: "<fugue-tunnel-id>"
  api_key: "file:<private-runtime-api-key-file>"
health:
  listen_addr: "127.0.0.1:0"
  url_file: "<private-health-url-file>"
admin_ui:
  open_browser: false
log:
  level: info
  format: json
mcp:
  server_urls:
    - channel: main
      url: "http://127.0.0.1:4197/mcp"
  extra_headers:
    Authorization: "file:<fugue-auth-header-file>"
  discovery_extra_headers:
    Authorization: "file:<fugue-auth-header-file>"
```

With a syntactically valid dummy tunnel/control-plane credential and the real
file-backed Fugue bearer, `tunnel-client doctor` returned `ok`: profile loading,
tunnel ID, control-plane credential reference, MCP target reachability, the
plain/non-OAuth metadata contract, and loopback health binding all passed. This
validates the local profile boundary only; it does not prove OpenAI control-plane
authentication or create a tunnel.

The independent local security review is now complete; see
[the Fugue Dev MCP security review](mcp-security-review.md). Remote exposure still
requires a separately provisioned Secure MCP Tunnel/ChatGPT custom-app connection.
The current stored tunnel-admin credential was rejected by the OpenAI control
plane, so no Fugue tunnel was created and the existing Mac Bash tunnel was left
unchanged. An end-to-end tunnel probe belongs to that later provisioning step.
Passing those remote gates authorizes only the read-only development server; it
does not authorize installation into the live Fugue bundle or add messaging/write
authority.
