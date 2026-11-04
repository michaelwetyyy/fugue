# Fugue

Fugue is a local orchestration runtime and desktop cockpit for coordinated AI-agent work. A durable controller manages scoped assignments, worker lifecycles, completion routing and recovery. A React/Tauri interface shows the resulting worker graph and operational state.

## Release status

This is an **experimental source release**, including the Python runtime, desktop source, tests and architecture documentation. It contains no live runtime database, credentials, session transcripts or private development history.

The core Python package has no runtime dependencies outside Python's standard library. Live deployment is currently macOS-specific. The managed desktop integration also expects separately installed, owner-validated OpenCode/Codex helper scripts; those machine-local helpers are not distributed here. This source release is not a turnkey desktop installer. The existing owner, mode, ancestry and digest checks remain in place.

## What is included

- A durable controller with explicit scope ownership, assignment fencing and retry identities.
- Queued work, disposable and persistent worker lifecycles, completion barriers and recovery.
- Bounded source capsules and policy checks for delegated work.
- An opt-in OpenCode HTTP/SSE adapter and completion callbacks.
- A metadata-first worker topology, source inbox and transcript/result views with explicit access boundaries.
- Synthetic process, protocol, lifecycle and failure-handling tests.

`oc_rig`, `rigctl`, `oc-*` and the built-in lane names are compatibility identifiers. They do not contain credentials or a deployed operator's configuration.

## Start with source validation

Python 3.11 or newer is required:

```sh
PYTHONPATH=src python3 -m oc_rig.cli --version
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The tests use synthetic subprocesses and local socket/HTTP fixtures. Some macOS security-policy tests create and clean temporary directories under the current user's home to obtain owner-controlled ancestry. They do not require the original author's interpreter or runtime cache.

The desktop frontend can be tested and built separately:

```sh
cd ui
pnpm install --frozen-lockfile
pnpm test
pnpm build
```

See [BUILDING.md](BUILDING.md) for toolchains, packaging and operational boundaries.

## Running the desktop

Building and launching are separate operations. A normal native desktop launch can attach to or start an existing managed Fugue installation in the login user's profile. It is an explicit live operation, not a source-only smoke test. Closing the macOS window hides the app; use its Quit command to exit.

The optional `dev-lab` profile uses synthetic controller data and disables live task delivery, but starts a loopback development MCP listener and creates a local authorization file. It is not a side-effect-free browser preview. Its identity and directory isolation are described in [the MCP bridge documentation](docs/mcp-bridge.md).

Do not substitute an arbitrary script for a missing managed integration helper or remove its validation checks. Use the shipped `rigctl` API and the documented deployment interfaces when preparing a separately reviewed installation.

## Architecture and source map

| Area | Source |
| --- | --- |
| Controller, protocol and persistent state | `src/oc_rig/daemon`, `protocol`, `store` |
| Policy and source capsules | `src/oc_rig/policy` |
| Scheduling, delivery and recovery | `scheduler`, `transport`, `completion`, `recovery` |
| OpenCode integration | `src/oc_rig/adapters` |
| Local-user deployment and terminal lifecycle | `deployment`, `terminal_lifecycle.py` |
| Desktop UI and native boundary | `ui/src`, `ui/src-tauri/src` |
| Synthetic tests | `tests`, `ui/src/*.test.*` |

Read the [architecture](docs/architecture.md), [agent lifecycles](docs/agent-lifecycles.md), [GUI design](docs/gui-architecture.md), [source inbox](docs/source-inbox.md) and [runtime-directory policy](docs/runtime-directories.md). The [deployment guide](docs/local-user-deployment.md) and [cutover runbook](docs/attended-cutover-runbook.md) describe explicit operational changes; they are not build prerequisites.

## Licence

Project code is released under the [MIT licence](LICENSE). Bundled fonts and third-party material retain their own licences and notices; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
