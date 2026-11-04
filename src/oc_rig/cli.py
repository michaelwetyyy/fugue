"""Thin command-line client for the private Rig daemon."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections.abc import Sequence
from pathlib import Path

from oc_rig import __version__
from oc_rig.adapters.opencode_client import MAX_PROMPT_BYTES
from oc_rig.cockpit import (
    CockpitClient,
    normalize_snapshot,
    render_details,
    render_json,
    render_terminal,
)
from oc_rig.completion.codex_callback import validate_codex_thread_id
from oc_rig.policy.capsule import (
    MAX_SCOPE_ENVELOPE_BYTES,
    REVIEW_PROFILES,
    capsule_document,
    capture_scope_capsule,
    render_capsule_prompt,
    validate_capsule_envelope,
)
from oc_rig.policy.models import AdmissionRequest
from oc_rig.policy.engine import decide_standalone_worker
from oc_rig.protocol.client import RigClient, RigClientError
from oc_rig.policy.scope import inspect_scope


_PATCH_RANGE = re.compile(r"([1-9][0-9]{0,5}):([1-9][0-9]{0,5})\Z")


def build_parser() -> argparse.ArgumentParser:
    """Build the client parser without starting or importing live integrations."""
    parser = argparse.ArgumentParser(
        prog="rigctl",
        description="Fugue private controller client",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument("--socket", type=Path, help="private rigd Unix socket")
    parser.add_argument(
        "--approved-root",
        type=Path,
        help="approved root containing the private socket",
    )
    parser.add_argument(
        "--service-uid",
        type=int,
        help="expected dedicated rigd service UID",
    )
    parser.add_argument(
        "--client-gid",
        type=int,
        help="expected dedicated rigd client group ID",
    )
    parser.add_argument(
        "--identity-profile",
        choices=("dedicated-service", "local-user"),
        help="explicit socket identity profile (local-user is owner-only)",
    )
    parser.add_argument("--idempotency-id", help="stable retry identifier")
    subcommands = parser.add_subparsers(dest="command")
    subcommands.add_parser("health", help="read daemon health")
    subcommands.add_parser("server-version", help="read daemon and protocol versions")
    subcommands.add_parser("snapshot", help="read the controller snapshot")
    for command in ("cockpit", "status"):
        cockpit = subcommands.add_parser(
            command,
            help="render one explicit read-only cockpit refresh",
        )
        cockpit.add_argument(
            "--format",
            choices=("text", "json"),
            default="text",
            help="deterministic output format",
        )
        cockpit.add_argument(
            "--width",
            type=int,
            default=100,
            help="terminal width from 24 to 240 columns",
        )
        cockpit.add_argument(
            "--no-ansi",
            action="store_true",
            help="explicitly request the always-plain terminal renderer",
        )
        cockpit.add_argument(
            "--details",
            action="store_true",
            help="show every normalized diagnostic field as readable JSON",
        )
    dispatch = subcommands.add_parser(
        "dispatch", help="dispatch one already-assigned logical pool/work target"
    )
    dispatch.add_argument("pool")
    dispatch.add_argument("work_id")
    dispatch.add_argument("--payload-json", required=True)
    submit = subcommands.add_parser(
        "submit",
        help="claim, admit, reserve, and dispatch one bounded local-user task",
    )
    submit.add_argument(
        "lane",
        choices=("tensorhost", "homelab", "personal", "control", "hands-off"),
    )
    submit.add_argument("repository", type=Path)
    submit.add_argument(
        "--scope",
        action="append",
        required=True,
        help="repository-relative file or directory; repeat for multiple scopes",
    )
    submit.add_argument("--prompt")
    submit.add_argument(
        "--include-scope",
        action="store_true",
        help=(
            "embed exact declared PUBLIC file contents for a no-tool read-only review; "
            "directories and unsafe files are rejected locally"
        ),
    )
    submit.add_argument(
        "--review-profile",
        action="append",
        choices=tuple(sorted(REVIEW_PROFILES)),
        help="closed review profile for --include-scope; repeat as needed",
    )
    submit.add_argument(
        "--codex-thread-id",
        help="canonical lowercase Codex thread UUID for a local completion return route",
    )
    submit.add_argument(
        "--reservation-attempt",
        type=int,
        default=1,
        help="positive retry generation; increment only after a confirmed queued result",
    )
    submit.add_argument(
        "--classification",
        choices=("PUBLIC", "SANITIZED", "SENSITIVE"),
        required=True,
    )
    submit.add_argument("--trust", choices=("secure",), required=True)
    submit.add_argument(
        "--risk-category",
        action="append",
        default=[],
        choices=(
            "sensitive",
            "credential",
            "production",
            "operator_gated",
            "destructive",
            "purchase",
            "signature",
            "filing",
            "external_commitment",
        ),
        help="declared task risk; repeat when more than one applies",
    )
    proposal = subcommands.add_parser(
        "proposal-submit",
        help="submit one capsule-bound no-tool task proposal",
    )
    proposal.add_argument(
        "lane",
        choices=("tensorhost", "homelab", "personal", "control", "hands-off"),
    )
    proposal.add_argument("repository", type=Path)
    proposal.add_argument("--scope", action="append", required=True)
    proposal.add_argument("--objective", required=True)
    proposal.add_argument("--submission-id", required=True)
    proposal.add_argument(
        "--agent-lifecycle",
        choices=("disposable", "persistent"),
        required=True,
    )
    proposal.add_argument("--codex-thread-id")
    proposal.add_argument("--reservation-attempt", type=int, default=1)
    proposal.add_argument(
        "--workspace-edit",
        action="store_true",
        help="apply a validated worker edit plan directly to the declared files",
    )
    proposal.add_argument(
        "--workspace-patch",
        help="apply one validated inclusive line range START:END",
    )
    transport_status = subcommands.add_parser(
        "transport-status", help="read logical transport state"
    )
    transport_status.add_argument("pool")
    transport_status.add_argument("work_id")
    cancel = subcommands.add_parser("cancel-transport", help="cancel a prepared transport")
    cancel.add_argument("pool")
    cancel.add_argument("work_id")
    reconcile_cancelled = subcommands.add_parser(
        "reconcile-cancelled-transport",
        help="finish one exact operator-cancelled accepted transport",
    )
    reconcile_cancelled.add_argument("pool")
    reconcile_cancelled.add_argument("work_id")
    reconcile_callback = subcommands.add_parser(
        "reconcile-callback-delivery",
        help="resolve one ambiguous local Codex callback from durable delivery proof",
    )
    reconcile_callback.add_argument("callback_id")
    completion = subcommands.add_parser(
        "accept-completion", help="record one registered work generation"
    )
    completion.add_argument("registration_id")
    completion.add_argument("work_id")
    completion.add_argument("generation", type=int)
    completion.add_argument("outcome", choices=("succeeded", "failed", "cancelled"))
    completion.add_argument("completion_key")
    result = subcommands.add_parser(
        "completion-result", help="read one exact durable terminal review result"
    )
    result.add_argument("result_ref")
    observe = subcommands.add_parser(
        "observe-recovery", help="record one recovery state event"
    )
    observe.add_argument("target_id")
    observe.add_argument("work_id")
    observe.add_argument("generation", type=int)
    observe.add_argument(
        "phase",
        choices=(
            "queued", "active", "handed_off", "tool_flow", "busy",
            "thinking", "corpse", "completed", "attention",
        ),
    )
    observe.add_argument("--productive", action="store_true")
    observe.add_argument(
        "--evidence", choices=("none", "callback", "claim", "completion"), default="none"
    )
    fire = subcommands.add_parser("fire-recovery-timer", help="fire one explicit due event")
    fire.add_argument("timer_id")
    recovery_result = subcommands.add_parser(
        "record-recovery-result", help="record one bounded recovery action result"
    )
    recovery_result.add_argument("episode_id")
    recovery_result.add_argument("attempt", type=int)
    recovery_result.add_argument(
        "result", choices=("progress", "no_progress", "transient_failure", "terminal_failure")
    )
    recovery_result.add_argument("reason")
    recovery_result.add_argument("--failure-class")
    return parser


def _submission_identifier(base: str, purpose: str) -> str:
    """Derive a bounded stable protocol identifier for one submission stage."""
    digest = hashlib.sha256(base.encode("utf-8")).hexdigest()
    return f"submit-{purpose}-{digest}"


def _resolve_codex_thread_id(explicit: object) -> str | None:
    """Resolve one optional trusted route without silently overriding either source."""
    environment = os.environ.get("CODEX_THREAD_ID")
    try:
        explicit_id = (
            None if explicit is None else validate_codex_thread_id(explicit)
        )
        environment_id = (
            None if environment is None else validate_codex_thread_id(environment)
        )
    except ValueError as error:
        raise RigClientError("invalid_codex_thread_id", str(error)) from error
    if (
        explicit_id is not None
        and environment_id is not None
        and explicit_id != environment_id
    ):
        raise RigClientError(
            "codex_thread_id_mismatch",
            "--codex-thread-id does not match CODEX_THREAD_ID",
        )
    return explicit_id if explicit_id is not None else environment_id


def _reject_submission(
    client: RigClient,
    base: str,
    claim: dict[str, object],
    operation_id: str,
) -> None:
    required = ("claim_id", "owner_id", "attempt", "fence_token")
    if any(field not in claim for field in required):
        raise RigClientError(
            "invalid_claim",
            "daemon claim response omitted exact release authority",
        )
    result = client.call(
        "submission.reject.v1",
        {**{field: claim[field] for field in required}, "operation_id": operation_id},
        idempotency_id=_submission_identifier(base, "reject-submission"),
    )
    if result.get("operation_state") != "failed" or result.get("claim_state") != "released":
        raise RigClientError(
            "submission_reject_failed",
            "invalid submission retained active authority",
        )


def _submit(client: RigClient, args: argparse.Namespace) -> tuple[int, dict[str, object]]:
    """Run the existing guarded daemon operations as one retryable CLI workflow."""
    base = args.idempotency_id
    codex_thread_id = _resolve_codex_thread_id(args.codex_thread_id)
    operation_id = _submission_identifier(base, "operation")
    work_id = _submission_identifier(base, "work")
    repository = str(args.repository.resolve())
    scope = list(args.scope)
    inspected = inspect_scope(repository, scope)
    if not inspected.accepted or inspected.repository is None:
        raise RigClientError("invalid_scope", "scope failed local policy preflight")
    normalized_repository = str(inspected.repository)
    normalized_scope = [path.relative for path in inspected.paths]
    if args.include_scope:
        if args.prompt is not None:
            raise RigClientError(
                "scope_capsule_prompt_forbidden",
                "--include-scope does not accept --prompt",
            )
        if args.classification != "PUBLIC":
            raise RigClientError(
                "scope_capsule_requires_public",
                "--include-scope requires --classification PUBLIC",
            )
        profiles = sorted(args.review_profile or [])
        capsule = capture_scope_capsule(
            normalized_repository,
            normalized_scope,
        )
        envelope_document: dict[str, object] = {
            "claim_scope_hash": capsule.claim_scope_hash,
            "review_profiles": profiles,
            "scope": normalized_scope,
            "scope_capsule": capsule_document(capsule),
            "task_mode": "read_only_review",
            "version": 2,
        }
        validate_capsule_envelope(envelope_document)
        worker_envelope = render_capsule_prompt(envelope_document)
        envelope_limit = MAX_SCOPE_ENVELOPE_BYTES
    else:
        if args.review_profile:
            raise RigClientError(
                "review_profile_requires_scope",
                "--review-profile requires --include-scope",
            )
        if args.prompt is None:
            raise RigClientError("prompt_required", "submit requires --prompt")
        capsule = None
        envelope_document = {
            "prompt": args.prompt,
            "repository": normalized_repository,
            "scope": normalized_scope,
            "version": 1,
        }
        envelope_limit = MAX_PROMPT_BYTES
        worker_envelope = json.dumps(
            envelope_document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    try:
        envelope_bytes = len(worker_envelope.encode("utf-8"))
    except UnicodeError as error:
        raise RigClientError(
            "prompt_invalid", "worker envelope is not valid UTF-8"
        ) from error
    if envelope_bytes > envelope_limit:
        raise RigClientError(
            "prompt_too_large",
            f"canonical worker envelope exceeds {envelope_limit} UTF-8 bytes",
        )
    if capsule is not None:
        local_decision = decide_standalone_worker(
            AdmissionRequest(
                repository=normalized_repository,
                scope=normalized_scope,
                content=worker_envelope,
                dispatch_kind="automated",
                trust=args.trust,
                classification=args.classification,
                risk_categories=list(args.risk_category),
            )
        )
        if not local_decision.allowed:
            raise RigClientError(
                "scope_capsule_preflight_rejected",
                "scope capsule failed local admission preflight",
            )

    client.call(
        "operation.create.v1",
        {"operation_id": operation_id, "kind": "dispatch"},
        idempotency_id=_submission_identifier(base, "create"),
    )
    claim = client.call(
        "scope.claim.v1",
        {
            "owner_operation_id": operation_id,
            "repository": repository,
            "scope": scope,
        },
        idempotency_id=_submission_identifier(base, "claim"),
    )
    if (
        claim.get("repository") != normalized_repository
        or claim.get("scope") != normalized_scope
    ):
        _reject_submission(client, base, claim, operation_id)
        raise RigClientError(
            "invalid_claim",
            "daemon claim did not match the preflight-normalized repository and scope",
        )
    if capsule is not None and claim.get("scope_hash") != capsule.claim_scope_hash:
        _reject_submission(client, base, claim, operation_id)
        raise RigClientError(
            "invalid_claim",
            "daemon claim hash did not match the captured review scope",
        )
    enqueue = client.call(
        "scheduler.enqueue.v1",
        {"work_id": work_id, "lane": args.lane},
        idempotency_id=_submission_identifier(base, "enqueue"),
    )
    admission = client.call(
        "scheduler.admit.v1",
        {
            "work_id": work_id,
            "claim_id": claim["claim_id"],
            "repository": normalized_repository,
            "scope": normalized_scope,
            "content": worker_envelope,
            "dispatch_kind": "automated",
            "trust": args.trust,
            "classification": args.classification,
            "risk_categories": list(args.risk_category),
        },
        idempotency_id=_submission_identifier(base, "admit"),
    )
    result: dict[str, object] = {
        "work_id": work_id,
        "lane": args.lane,
        "scope": {
            "repository": normalized_repository,
            "paths": normalized_scope,
            "scope_hash": claim.get("scope_hash"),
        },
        "enqueue": dict(enqueue),
        "admission": dict(admission),
    }
    if admission.get("allowed") is not True:
        if capsule is not None:
            _reject_submission(client, base, claim, operation_id)
        else:
            released = client.call(
                "scope.release.v1",
                {field: claim[field] for field in ("claim_id", "owner_id", "attempt", "fence_token")},
                idempotency_id=_submission_identifier(base, "reject-release"),
            )
            if released.get("released") is not True:
                raise RigClientError("scope_release_failed", "rejected submission retained its active scope claim")
        result["scope_released"] = True
        result["state"] = "rejected"
        return 2, result

    reservation_result = client.call(
        "scheduler.reserve.v1",
        {"work_id": work_id},
        idempotency_id=_submission_identifier(
            base, f"reserve-{args.reservation_attempt}"
        ),
    )
    reservation = reservation_result.get("reservation")
    if not isinstance(reservation, dict):
        result["state"] = "queued"
        return 2, result
    if reservation.get("work_id") != work_id or reservation.get("lane") != args.lane:
        raise RigClientError(
            "reservation_mismatch",
            "target-bound scheduler reservation did not match the submission",
        )

    dispatch_params: dict[str, object] = {
        "pool": args.lane,
        "work_id": work_id,
        "reservation_id": reservation["id"],
        "reservation_attempt": reservation["attempt"],
        "reservation_fence": reservation["fence_token"],
        "payload": {
            "prompt": worker_envelope,
            "classification": args.classification,
            "trust": args.trust,
        },
    }
    if codex_thread_id is not None:
        dispatch_params["return_route"] = {
            "kind": "local_codex",
            "thread_id": codex_thread_id,
        }
    transport = client.call(
        "transport.dispatch.v1",
        dispatch_params,
        idempotency_id=_submission_identifier(
            base, f"dispatch-{args.reservation_attempt}"
        ),
    )
    transport_state = transport.get("state", "unknown")
    if transport_state == "definite_failed" and transport.get("error_code") == "no_capacity":
        result["state"] = "queued"
        result["transport"] = {"state": transport_state, "error_code": "no_capacity"}
        return 2, result
    result["transport"] = {
        key: transport.get(key)
        for key in ("transport_id", "state", "attempt", "error_code")
    }
    result["state"] = transport_state
    return (0 if transport_state == "accepted" else 1), result


def main(argv: Sequence[str] | None = None) -> int:
    """Send one request and print its JSON result."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        return 0
    if args.socket is None:
        parser.error("--socket is required for daemon commands")
    if args.identity_profile == "local-user":
        if args.service_uid is not None or args.client_gid is not None:
            parser.error("local-user profile does not accept service identity fields")
    elif args.service_uid is None or args.client_gid is None:
        parser.error(
            "dedicated-service requires --service-uid and --client-gid; "
            "local-user must be selected explicitly"
        )
    if args.command in {"cockpit", "status"}:
        if not 24 <= args.width <= 240:
            parser.error("--width must be between 24 and 240")
        client = CockpitClient(
            args.socket,
            approved_root=args.approved_root,
            service_uid=args.service_uid,
            client_gid=args.client_gid,
            identity_profile=args.identity_profile,
        )
        try:
            snapshot = client.refresh()
        except (OSError, RigClientError, ValueError) as error:
            print(f"rigctl: {error}", file=sys.stderr)
            return 1
        normalized = normalize_snapshot(snapshot)
        if args.details:
            print(render_details(snapshot), end="")
        elif args.format == "json":
            print(render_json(snapshot))
        else:
            print(
                render_terminal(snapshot, width=args.width, ansi=False),
                end="",
            )
        return 0 if normalized["availability"]["status"] == "available" else 2
    request_idempotency = args.idempotency_id
    operations: dict[str, tuple[str, dict[str, object]]] = {
        "health": ("health.v1", {}),
        "server-version": ("version.v1", {}),
        "snapshot": ("scheduler.snapshot.v1", {}),
    }
    if args.command == "proposal-submit":
        if args.idempotency_id is not None:
            parser.error("proposal-submit derives its idempotency identity")
        if not 1 <= args.reservation_attempt <= 32:
            parser.error("--reservation-attempt must be between 1 and 32")
        try:
            thread_id = _resolve_codex_thread_id(args.codex_thread_id)
        except RigClientError as error:
            parser.error(str(error))
        params = {
            "submission_id": args.submission_id,
            "lane": args.lane,
            "repository": str(args.repository),
            "scope": list(args.scope),
            "objective": args.objective,
            "agent_lifecycle": args.agent_lifecycle,
            "allow_child_agents": True,
            "classification": "PUBLIC",
            "trust": "secure",
            "reservation_attempt": args.reservation_attempt,
        }
        if args.workspace_edit:
            params["workspace_edit"] = True
        if args.workspace_patch is not None:
            if args.workspace_edit:
                parser.error("workspace edit modes are mutually exclusive")
            match = _PATCH_RANGE.fullmatch(args.workspace_patch)
            if match is None or int(match.group(1)) > int(match.group(2)):
                parser.error("--workspace-patch must be START:END")
            params["workspace_patch"] = {
                "line_start": int(match.group(1)),
                "line_end": int(match.group(2)),
            }
        if thread_id is not None:
            params["return_route"] = {
                "kind": "local_codex",
                "thread_id": thread_id,
            }
        operation = "submission.submit.v1"
        request_idempotency = (
            f"gui-submit-{args.submission_id}-attempt-{args.reservation_attempt}"
        )
    elif args.command == "dispatch":
        try:
            payload = json.loads(args.payload_json)
        except json.JSONDecodeError as error:
            parser.error(f"--payload-json is invalid JSON: {error.msg}")
        if not isinstance(payload, dict):
            parser.error("--payload-json must contain an object")
        operation, params = (
            "transport.dispatch.v1",
            {"pool": args.pool, "work_id": args.work_id, "payload": payload},
        )
    elif args.command == "transport-status":
        operation, params = (
            "transport.status.v1",
            {"pool": args.pool, "work_id": args.work_id},
        )
    elif args.command == "cancel-transport":
        operation, params = (
            "transport.cancel.v1",
            {"pool": args.pool, "work_id": args.work_id},
        )
    elif args.command == "reconcile-cancelled-transport":
        operation, params = (
            "transport.reconcilecancelled.v1",
            {"pool": args.pool, "work_id": args.work_id},
        )
    elif args.command == "reconcile-callback-delivery":
        operation, params = (
            "callback.delivery.reconcile.v1",
            {"callback_id": args.callback_id},
        )
    elif args.command == "accept-completion":
        operation, params = (
            "completion.accept.v1",
            {
                "completion_key": args.completion_key,
                "registration_id": args.registration_id,
                "work_id": args.work_id,
                "generation": args.generation,
                "outcome": args.outcome,
            },
        )
    elif args.command == "completion-result":
        operation, params = (
            "completion.result.v1",
            {"result_ref": args.result_ref},
        )
    elif args.command == "observe-recovery":
        operation, params = (
            "recovery.observe.v1",
            {
                "target_id": args.target_id,
                "work_id": args.work_id,
                "generation": args.generation,
                "phase": args.phase,
                "productive": args.productive,
                "evidence": args.evidence,
            },
        )
    elif args.command == "fire-recovery-timer":
        operation, params = "recovery.timer.fire.v1", {"timer_id": args.timer_id}
    elif args.command == "record-recovery-result":
        operation, params = (
            "recovery.attempt.record.v1",
            {
                "episode_id": args.episode_id,
                "attempt": args.attempt,
                "result": args.result,
                "failure_class": args.failure_class,
                "reason": args.reason,
            },
        )
    elif args.command == "submit":
        operation, params = "", {}
    else:
        operation, params = operations[args.command]
    client = RigClient(
        args.socket,
        approved_root=args.approved_root,
        service_uid=args.service_uid,
        client_gid=args.client_gid,
        identity_profile=args.identity_profile,
    )
    try:
        if args.command == "submit":
            if args.idempotency_id is None:
                parser.error("submit requires --idempotency-id for safe retries")
            if args.reservation_attempt <= 0:
                parser.error("--reservation-attempt must be positive")
            status, result = _submit(client, args)
            print(
                json.dumps(
                    result,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return status
        result = client.call(
            operation,
            params,
            idempotency_id=request_idempotency,
        )
    except (OSError, RigClientError, ValueError) as error:
        print(f"rigctl: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    if args.command == "proposal-submit":
        return 0 if result.get("state") == "accepted" else 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
