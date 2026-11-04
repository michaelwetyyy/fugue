# Building and validating Fugue

## Source-release scope

This release publishes source, not a signed/notarized desktop binary or a configured live installation. No published command below installs a controller, starts OpenCode, arms delegation or sends a task. Operational commands in `docs/` require their own reviewed configuration.

## Validation environment

The release preparation environment uses a Python 3.14.7 test runner with a separately selected, owner-controlled Python 3.12.14 for deployment-policy fixtures, plus Node 26.3.0, Rust 1.98.1 and Cargo 1.98.1 on macOS. The UI declares pnpm 11.25.0 in `packageManager`; use that pinned manager with the supplied lockfile. Dependency installation may need registry access and the native Rust build needs the appropriate Tauri platform SDK prerequisites. These environment versions are not claims of validation on other operating systems.

## Python

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m oc_rig.cli --version
```

The synthetic test harness creates local child processes and sockets. Set `FUGUE_TEST_PYTHON=/absolute/path/to/owned/python3` when deployment-policy fixtures need a different interpreter from the test runner. The override must be absolute; the existing deployment pin and ancestry checks still apply. The interpreter executable and its ancestry must be root/user-owned and not group-writable. A group-writable package-manager prefix does not satisfy that boundary; use an owner-controlled Python installation for the deployment-policy suite. Do not relax the production pin checks or change global directory permissions to make the tests pass. Owner-controlled temporary home subdirectories used by macOS ancestry-policy tests are cleaned by test teardown. Preserve the security checks; replacing the test root with a world-writable ancestor changes what those tests exercise.

The offline wheel builder does not install anything:

```sh
mkdir -p /path/to/empty-output
PYTHONPATH=src python3 tools/build_release.py \
  --source-root . --output-directory /path/to/empty-output
```

Outputs are immutable. To check reproducibility, build into two different empty output directories and compare wheel hashes. The wheel includes the MIT licence, an exact RECORD and a member manifest. Historical-artifact compatibility is an explicit verifier option; new artifacts require the complete current membership.

## Frontend and native source

```sh
cd ui
pnpm install --frozen-lockfile
pnpm test
pnpm build
cargo test --locked --manifest-path src-tauri/Cargo.toml
cargo test --locked --manifest-path src-tauri/Cargo.toml --features dev-lab
```

`pnpm build` produces frontend assets. Cargo tests compile native modules and run their test harness; neither command launches the desktop. Do not equate a successful build with a configured or tested live installation. The standard-library runtime and the native desktop have different platform requirements.

## Live integration boundary

Normal native GUI startup calls the managed lifecycle in the login profile. It may start or attach to installed services and continues running when its window is hidden. The `dev-lab` executable uses synthetic data but creates its own authorization state and starts a loopback MCP service. Do not use either startup mode as an unattended build/CI smoke test.

The production integration bridge intentionally validates separately installed `oc-integration` helpers by owner, mode, ancestry, exact wrapper bytes and script digest. Those operator-managed artifacts are not part of this publication. The source-inbox integration also pins a supported macOS Codex executable layout. No portable live installation or integration-helper provisioning is claimed by this release.

Install, configure, start, stop, rollback, uninstall and explicit source/callback operations are documented in the deployment and MCP guides. Their effects are separate from source validation. No live runtime or profile was exported into this repository.
