# Runtime-directory policy

Source and mutable runtime data must remain physically separate. A clean clone
must contain no machine-specific state and running Fugue must not write into
its source checkout.

## macOS layout

| Purpose | Location |
|---|---|
| Durable controller state | `~/Library/Application Support/oc-rig/` |
| Caches and generated data | `~/Library/Caches/oc-rig/` |
| Operational logs | `~/Library/Logs/oc-rig/` |

The future secure-worker workspace is separately configured and is not owned by
this source repository. Its location must never be inferred and created by the
bootstrap.

## Rules

- The repository contains source, static configuration defaults, documentation,
  and tests only.
- SQLite databases, write-ahead logs, lock files, generated state, and process
  identifiers live under the durable state directory.
- Logs and caches never become an authority for controller state.
- Credentials, tokens, cookies, browser profiles, conversation sessions, and
  environment files containing secrets are prohibited from the repository.
- Runtime directories are created only by an explicit future setup or start
  operation, with restrictive permissions and no symlink traversal.
- Tests use temporary directories supplied by the test harness; they do not use
  or mutate the real macOS runtime locations.
- Migration reads from an operator-selected snapshot, never directly from a
  running Rig v1 directory.

`oc_rig.runtime.RuntimeDirectories` calculates the first three paths without
performing filesystem I/O. Path calculation does not authorise directory
creation or access.

The separate, explicitly selected macOS single-user deployment layout and its
owner-only runtime boundary are documented in
[macOS local-user deployment profile](local-user-deployment.md). It does not
change the dedicated-service production topology.
