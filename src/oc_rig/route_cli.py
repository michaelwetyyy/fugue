"""Narrow Codex-facing facade for PUBLIC Fugue reviews and bounded work."""

from __future__ import annotations

import argparse
import re
from collections.abc import Sequence
from pathlib import Path

from oc_rig import cli
from oc_rig.completion.codex_callback import validate_codex_thread_id
from oc_rig.policy.capsule import REVIEW_PROFILES


_IDEMPOTENCY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_PATCH_RANGE = re.compile(r"([1-9][0-9]{0,5}):([1-9][0-9]{0,5})\Z")
_LANES = ("tensorhost", "homelab", "personal", "control", "hands-off")


def build_parser() -> argparse.ArgumentParser:
    """Expose bounded reads, reviews, proposals, and direct workspace edits."""

    parser = argparse.ArgumentParser(
        prog="oc-route",
        description="Verified Codex route for PUBLIC Fugue work",
    )
    parser.add_argument("deployment_root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("codex_thread_id", help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command")

    for command in ("status", "cockpit"):
        status = commands.add_parser(command, help="read one controller snapshot")
        status.add_argument("--format", choices=("text", "json"), default="text")
        status.add_argument("--width", type=int, default=100)
        status.add_argument("--details", action="store_true")

    result = commands.add_parser(
        "result", help="read one exact durable terminal review result"
    )
    result.add_argument("result_ref")

    review = commands.add_parser(
        "review", help="submit exact PUBLIC files for a no-tool read-only review"
    )
    review.add_argument("lane", choices=_LANES)
    review.add_argument("repository", type=Path)
    review.add_argument(
        "--scope",
        action="append",
        required=True,
        help="repository-relative file; repeat for multiple files",
    )
    review.add_argument(
        "--profile",
        action="append",
        required=True,
        choices=tuple(sorted(REVIEW_PROFILES)),
        help="closed review profile; repeat as needed",
    )
    review.add_argument(
        "--idempotency-id",
        required=True,
        help="stable retry identifier",
    )
    task = commands.add_parser(
        "task",
        help="submit exact PUBLIC files for a no-tool implementation proposal",
    )
    task.add_argument("lane", choices=_LANES)
    task.add_argument("repository", type=Path)
    task.add_argument(
        "--scope",
        action="append",
        required=True,
        help="repository-relative file; repeat for multiple files",
    )
    task.add_argument(
        "--objective",
        required=True,
        help="bounded objective; worker returns a proposal and cannot write files",
    )
    task.add_argument(
        "--lifecycle",
        choices=("disposable", "persistent"),
        required=True,
    )
    task.add_argument(
        "--idempotency-id",
        required=True,
        help="stable retry identifier",
    )
    task.add_argument(
        "--reservation-attempt",
        type=int,
        default=1,
        help="positive retry generation after a confirmed busy result",
    )
    work = commands.add_parser(
        "work",
        help="edit exact PUBLIC files through the local scope broker",
    )
    work.add_argument("lane", choices=_LANES)
    work.add_argument("repository", type=Path)
    work.add_argument(
        "--scope",
        action="append",
        required=True,
        help="one repository-relative existing file",
    )
    work.add_argument("--objective", required=True, help="bounded edit objective")
    work.add_argument(
        "--lifecycle",
        choices=("disposable", "persistent"),
        required=True,
    )
    work.add_argument("--idempotency-id", required=True, help="stable retry identifier")
    work.add_argument(
        "--reservation-attempt",
        type=int,
        default=1,
        help="positive retry generation after a confirmed busy result",
    )
    patch = commands.add_parser(
        "patch",
        help="edit one bounded line window through the local scope broker",
    )
    patch.add_argument("lane", choices=_LANES)
    patch.add_argument("repository", type=Path)
    patch.add_argument("--scope", action="append", required=True, help="one existing file")
    patch.add_argument("--lines", required=True, help="editable inclusive line range START:END")
    patch.add_argument("--objective", required=True, help="bounded patch objective")
    patch.add_argument("--lifecycle", choices=("disposable",), required=True)
    patch.add_argument("--idempotency-id", required=True, help="stable retry identifier")
    patch.add_argument("--reservation-attempt", type=int, default=1)
    return parser


def _connection(root: Path) -> list[str]:
    if not root.is_absolute():
        raise ValueError("deployment root must be absolute")
    socket_root = root / "runtime" / "socket-boundary"
    return [
        "--socket",
        str(socket_root / "socket" / "rig.sock"),
        "--approved-root",
        str(socket_root),
        "--identity-profile",
        "local-user",
    ]


def main(argv: Sequence[str] | None = None) -> int:
    """Translate the narrow grammar into fixed, guarded ``rigctl`` arguments."""

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        connection = _connection(args.deployment_root)
    except ValueError as error:
        parser.error(str(error))

    if args.command in {"status", "cockpit"}:
        forwarded = [
            *connection,
            args.command,
            "--format",
            args.format,
            "--width",
            str(args.width),
        ]
        if args.details:
            forwarded.append("--details")
        return cli.main(forwarded)

    if args.command == "result":
        return cli.main([*connection, "completion-result", args.result_ref])

    if _IDEMPOTENCY_ID.fullmatch(args.idempotency_id) is None:
        parser.error("--idempotency-id must be 1-128 safe identifier characters")
    thread_id = args.codex_thread_id
    if thread_id == "-":
        parser.error("CODEX_THREAD_ID is required for completion delivery")
    try:
        validate_codex_thread_id(thread_id)
    except ValueError as error:
        parser.error(str(error))

    if args.command in {"task", "work", "patch"}:
        if args.command in {"work", "patch"} and len(args.scope) != 1:
            parser.error(f"{args.command} requires exactly one existing --scope file")
        if not 1 <= args.reservation_attempt <= 32:
            parser.error("--reservation-attempt must be between 1 and 32")
        try:
            objective_size = len(args.objective.encode("utf-8"))
        except UnicodeError:
            parser.error("--objective must be valid UTF-8")
        unsafe = {
            "\x00", "\x7f", "\u061c", "\u200e", "\u200f", "\u2028", "\u2029",
            "\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067",
            "\u2068", "\u2069",
        }
        if (
            not args.objective.strip()
            or objective_size > 4096
            or any(character in unsafe for character in args.objective)
        ):
            parser.error("--objective is invalid or exceeds 4,096 UTF-8 bytes")
        forwarded = [
            *connection,
            "proposal-submit",
            args.lane,
            str(args.repository),
            "--objective",
            args.objective.strip(),
            "--submission-id",
            args.idempotency_id,
            "--agent-lifecycle",
            args.lifecycle,
            "--codex-thread-id",
            thread_id,
            "--reservation-attempt",
            str(args.reservation_attempt),
        ]
        for scope in args.scope:
            forwarded.extend(("--scope", scope))
        if args.command == "work":
            forwarded.append("--workspace-edit")
        elif args.command == "patch":
            match = _PATCH_RANGE.fullmatch(args.lines)
            if match is None or int(match.group(1)) > int(match.group(2)):
                parser.error("--lines must be an inclusive START:END range")
            forwarded.extend(("--workspace-patch", args.lines))
        return cli.main(forwarded)

    forwarded = [
        *connection,
        "--idempotency-id",
        args.idempotency_id,
        "submit",
        args.lane,
        str(args.repository),
        "--codex-thread-id",
        thread_id,
    ]
    for scope in args.scope:
        forwarded.extend(("--scope", scope))
    forwarded.append("--include-scope")
    for profile in args.profile:
        forwarded.extend(("--review-profile", profile))
    forwarded.extend(("--classification", "PUBLIC", "--trust", "secure"))
    return cli.main(forwarded)


if __name__ == "__main__":
    raise SystemExit(main())
