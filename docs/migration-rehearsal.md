# Offline reversible migration rehearsal

Milestone 10 is an entirely synthetic exercise. It has no command, argument, or
fallback that discovers Rig v1, the user's home directory, the default OC Rig
runtime, OpenCode, or tmux. Every writable path must be below an explicitly
marked child of the operating-system temporary directory.

## Rehearsal boundary

The only accepted source is
`tests/fixtures/migration_v1_minimal.json`. The runner copies that reviewable
fixture into its synthetic root before validation. Its exact compatibility
format contains:

- schema version and migration identity;
- a legacy controller whose only accepted state is `stopped`; and
- one to eight queued records containing only ID, lane, state, and timestamp.

Unknown fields, unsupported versions, non-stopped controllers, links (including
hardlinks), special files, unexpected owners, group/world-writable modes,
changed file identities, changed bytes, paths outside the marked root, and
non-fresh destinations are rejected before logical import. The final source
identity and byte revalidation occurs inside the one SQLite transaction before
commit. A stable migration ID and source hash make an exact repeat a no-op and
reject reuse with different bytes.

## Immutable candidate

`tools/build_release.py` constructs a byte-reproducible wheel with only the
standard library. It performs no package installation and no network access.
The wheel and JSON manifest are made read-only. The manifest hashes the wheel
and every member. Verification requires exactly migrations `001` through `010`,
requires the canonical `oc_rig-<version>.dist-info/RECORD` and exact canonical
distribution metadata membership, validates complete wheel `RECORD` membership,
hashes, and sizes, and rejects extra/missing migrations, renamed or foreign
distribution metadata, tests, fixtures, caches, bytecode, duplicate members,
traversal paths, and undeclared members.

## Executable exercise

From a clean checkout, run the focused warning-strict gate:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 -W error -m unittest tests.migration_rehearsal_suite -v
```

Run one attended-to-the-output synthetic rehearsal in a fresh temporary root:

```bash
rehearsal_root="$(mktemp -d "${TMPDIR%/}/oc-rig-v2-rehearsal.XXXXXX")"
chmod 0700 "$rehearsal_root"
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 -W error tools/migration_rehearsal.py --root "$rehearsal_root"
```

The runner:

1. builds and verifies the immutable candidate;
2. takes byte-hashed source and absent-destination snapshots;
3. validates the stopped synthetic source before any destination write;
4. imports into a fresh v2 database in one transaction;
5. starts the durable v2 daemon on a private temporary socket from the verified
   wheel's bytes copied before launch to a fresh anonymous read-only inode; on
   Linux the copy is a sealed memfd when available, and otherwise it is a
   private mode-`0400` regular file reopened read-only and unlinked before the
   hook or child can run. Only that no-alias copy is imported under isolated
   `-I -S -B` interpreter flags, with no pathname import, checkout or test
   fixture import and with disabled transport and callback adapters. The child
   re-verifies both inherited descriptors and reports the copy kind, zero link
   count, hashes, and inode provenance. Its private `HOME` is inode-recorded at
   creation, atomically moved out of the reusable `candidate-home` pathname on
   every launch failure and shutdown, descriptor-revalidated, and retained as
   tracked evidence without a pathname-based delete. Its guard binds stable
   directory facts (device, inode, type/mode, UID, and GID), so legitimate
   files, nested directories, and symlinks created during the candidate's life
   remain intact in evidence; link-count changes do not invalidate cleanup;
6. verifies SQLite health, no external dependencies, migrations `001`–`009`,
   one exact queued record, five lanes, eleven slots, and explicit one-shot
   cockpit refresh;
7. stops the candidate, validates the backup before touching the destination,
   verifies a sibling staging copy, inode-guards and atomically swaps the
   destination while retaining the original until success, revalidates the
   retained inode before installing staging and again after an atomic,
   dirfd-relative evidence quarantine. The quarantined original is retained
   without pathname deletion; any substitution fails closed without deleting
   either inode. The runner safely unwinds each earlier rename phase and proves
   the source never changed.

The same runner accepts `--abort-phase` for `after_validation`,
`after_destination_initialize`, `before_import_commit`, `after_import`, and
`after_candidate_start`. The focused gate exercises every phase plus malformed
validation and verifies byte-identical rollback. `rehearsal-report.json` is a
small synthetic proof containing release, source, destination, topology, queue,
and cockpit hashes/facts. No runtime artifact is written to the checkout.

This exercise is not a live migration tool. Its report always says
`production_action_available: false`.
