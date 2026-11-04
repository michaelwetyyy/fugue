# Attended cutover readiness runbook

This runbook deliberately stops before any live action. It is a prerequisite
and gate checklist, not authorization to read or mutate Rig v1, provision the
host, start a production daemon, enable adapters, or switch controllers.

## Required immutable inputs

- Reviewed source revision and exact commit ID.
- Read-only wheel plus `oc-rig-release-manifest.json`, whose wheel hash and
  member hashes, exact canonical distribution metadata directory, and complete
  `RECORD` membership have been independently verified.
- Packaged migrations `001_initial.sql` through
  `010_local_codex_callbacks.sql`, with no fixture, test, cache, or
  bytecode members.
- A separately implemented and reviewed real Rig v1 export specification. The
  milestone-10 synthetic fixture is not valid for live data.
- Operator-selected, quiescent Rig v1 export and pre-cutover snapshot paths.
  No cutover component may discover a live directory.
- Explicit v2 state, socket, log, cache, repository, `HOME`, port, and tmux
  namespaces, all separate from Rig v1.

## External host provisioning requirements

These are external prerequisites and are not performed by the repository or
the rehearsal:

- a dedicated non-root rigd service UID with no shared login use;
- a dedicated client group used as rigd's effective GID, with an exact reviewed
  allowlist of non-root client UIDs; the service UID must differ from every
  client UID;
- service-owned state directory mode `0700`, database and lock mode `0600`;
- service-owned socket root and socket directory mode `0710`, assigned to the
  client group; the daemon socket is mode `0620`;
- on macOS, a canonical artifact root whose ancestors are root-owned,
  non-group/world-writable, and traversable, containing the pinned native
  bootstrap, Python interpreter, and rigd helper as root-owned, single-link,
  regular files at mode `0555`;
- recorded SHA-256, device, inode, size, owner, and mode pins for all three
  bootstrap artifacts, supplied explicitly to rigd and revalidated at launch;
  and
- a service manager definition that pins the release and all explicit paths,
  uses the dedicated identity, and cannot inherit Rig v1 environment or
  credentials.

Provisioning, identity/group changes, root-owned artifact installation, and
service-manager activation require their own authorized host change. They are
not part of this offline milestone.

## Gates before an attended window

Every gate must have a named owner, timestamp, immutable evidence location, and
explicit pass verdict:

1. The focused milestone-10 warning-strict suite passes with no skips.
2. The entire offline warning-strict suite passes with no unexpected skips.
3. An independent reviewer verifies the artifact, manifest, synthetic-only
   boundary, pre-commit source revalidation, complete wheel `RECORD`, daemon
   anonymous-copy wheel provenance, tracked launch-home evidence quarantine,
   twice-checked retained inode and deletion-free dirfd-relative quarantine,
   phase-safe staged atomic rollback, cockpit proof, abort matrix, and rollback
   hashes.
4. The real export format and importer are separately designed, reviewed, and
   exercised against authorized non-live copies. Milestone 10 does not provide
   this capability.
5. External identity, filesystem, bootstrap artifact, and service-manager
   provisioning is complete and independently verified without starting v2.
6. Rig v1 quiescence criteria, snapshot method, snapshot immutability, maximum
   cutover duration, abort thresholds, and health criteria are approved.
7. The rollback owner confirms the old controller can remain stopped but fully
   retained during candidate start, and that its snapshot will never be
   overwritten by v2.
8. the operator provides explicit attended authorization for the exact window and
   is present for every operator gate.

Any missing, stale, ambiguous, or failed gate is a stop. Hash mismatch, source
change, validation error, partial import, unexpected process, unexpected
socket/path, topology mismatch, adapter activity, or cockpit degradation is an
immediate rollback decision, not a troubleshooting window.

## Pre-approved rollback sequence

Before authorization, the operator and rollback owner must rehearse and sign
off this sequence against isolated copies:

1. fence new requests;
2. stop the v2 candidate and prove its process, socket, and children are gone;
3. retain the failed v2 state and logs as immutable evidence;
4. restore the pre-cutover destination bytes and verify their recorded hash;
5. verify the Rig v1 snapshot remains byte-identical and was never overwritten;
6. restart only the retained old controller using its pre-cutover authority;
7. verify old-controller health, topology, queue ownership, callbacks, and
   operator visibility before admitting work; and
8. record the rollback verdict and leave v2 disarmed.

Rollback after source validation failure occurs before import. Rollback after
import or candidate start additionally requires stopping and fencing v2 before
restoring any bytes. No step may infer a path, silently re-enable an adapter, or
delete either snapshot.

## Stop line

The offline milestone ends when the prerequisites, gates, and rollback plan
above are review-ready. The next action would involve live data, host
provisioning, service state, or controller authority and therefore requires a
separately reviewed, explicitly authorized, attended milestone-11 procedure.
Do not continue from this document into a live action.
