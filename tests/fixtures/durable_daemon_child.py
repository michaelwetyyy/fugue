"""Test-only durable child with a modeled authenticated peer UID."""

from __future__ import annotations

import os
import socket
import sqlite3
import weakref

from oc_rig.daemon import child
from oc_rig.adapters import AdapterResult, DisabledAdapter
from oc_rig.daemon import controller as controller_module
from oc_rig.scheduler.service import _Scheduler
from oc_rig.transport.service import _dispatch_transport
from oc_rig.daemon.server import _DurableChildDaemon
from oc_rig.daemon.security import PrivateSocketPath


def _modeled_handler(
    daemon: _DurableChildDaemon,
):
    client_uid = int(os.environ["OC_RIG_TEST_CLIENT_UID"])
    reference = weakref.ref(daemon)

    def handle(connection: socket.socket) -> None:
        current = reference()
        if current is None:
            connection.close()
            return
        current._serve_client(connection, lambda _connection: client_uid)

    return handle


_DurableChildDaemon._create_request_handler = _modeled_handler

_mode = os.environ.get("OC_RIG_TEST_DAEMON_MODE", "normal")
if _mode == "assert_registration_before_send":
    _ordered_send = DisabledAdapter.send

    def _assert_registration_before_send(*args: object, **kwargs: object):
        with sqlite3.connect(os.environ["OC_RIG_TEST_DATABASE"]) as connection:
            state = connection.execute(
                "SELECT state FROM transport_deliveries"
            ).fetchone()
            completion = connection.execute(
                "SELECT count(*) FROM transport_completion_registrations"
            ).fetchone()
            callback = connection.execute(
                "SELECT count(*) FROM transport_callback_registrations"
            ).fetchone()
        assert state == ("sending",)
        assert completion == (1,)
        assert callback == (1,)
        return _ordered_send(*args, **kwargs)

    DisabledAdapter.send = _assert_registration_before_send
elif _mode == "forbid_send":
    class _UnexpectedSend(BaseException):
        pass

    def _forbid_send(*_args: object, **_kwargs: object):
        raise _UnexpectedSend()

    DisabledAdapter.send = _forbid_send
elif _mode == "disconnect":
    def _disconnect(*_args: object, **_kwargs: object):
        raise ConnectionError("synthetic disconnect after send intent")

    DisabledAdapter.send = _disconnect
elif _mode == "crash_after_intent":
    class _CrashAfterIntent(BaseException):
        pass

    def _crash_after_intent(*_args: object, **_kwargs: object):
        raise _CrashAfterIntent()

    DisabledAdapter.send = _crash_after_intent
elif _mode == "crash_after_prepare":
    class _CrashAfterPrepare(BaseException):
        pass

    def _crash_after_prepare(*_args: object, **_kwargs: object):
        raise _CrashAfterPrepare()

    DisabledAdapter.prepare = _crash_after_prepare
elif _mode == "crash_after_transport":
    def _crash_after_transport(*args: object, **kwargs: object):
        _dispatch_transport(*args, **kwargs)
        raise RuntimeError("simulated crash after transport commit")

    controller_module._dispatch_transport = _crash_after_transport
elif _mode == "crash_after_enqueue":
    _original_enqueue = _Scheduler.enqueue

    def _crash_after_enqueue(*args: object, **kwargs: object):
        _original_enqueue(*args, **kwargs)
        raise RuntimeError("simulated process crash")

    _Scheduler.enqueue = _crash_after_enqueue
elif _mode == "no_capacity_once":
    _send_attempt = 0

    def _no_capacity_once(*_args: object, **_kwargs: object):
        global _send_attempt
        _send_attempt += 1
        if _send_attempt == 1:
            return AdapterResult.definite_failure("no_capacity")
        return AdapterResult.accepted("accepted-after-capacity")

    DisabledAdapter.send = _no_capacity_once
elif _mode == "review_agent_invalid":
    def _review_agent_invalid(*_args: object, **_kwargs: object):
        return AdapterResult.definite_failure("review_agent_invalid")

    DisabledAdapter.send = _review_agent_invalid
elif _mode == "delivery_unknown":
    def _delivery_unknown(*_args: object, **_kwargs: object):
        return AdapterResult.unknown("backend_delivery_unknown")

    DisabledAdapter.send = _delivery_unknown
elif _mode == "cancelled":
    def _cancelled(*_args: object, **_kwargs: object):
        return AdapterResult.cancelled("backend_cancelled")

    DisabledAdapter.send = _cancelled
elif _mode == "accepted":
    def _accepted(*_args: object, **_kwargs: object):
        return AdapterResult.accepted("backend-accepted")

    DisabledAdapter.send = _accepted
elif _mode == "accepted_abort_cancelled":
    def _accepted_abort(*_args: object, **_kwargs: object):
        return AdapterResult.accepted("backend-accepted")

    def _cancel_accepted(*_args: object, **_kwargs: object):
        return AdapterResult.cancelled("abort-acknowledged")

    DisabledAdapter.send = _accepted_abort
    DisabledAdapter.safe_abort = _cancel_accepted
elif _mode == "terminal_release_mismatch":
    def _terminal_release_mismatch(*_args: object, **_kwargs: object):
        return False

    _Scheduler.release = _terminal_release_mismatch
elif _mode == "bind_failure":
    def _bind_failure(*_args: object, **_kwargs: object):
        raise RuntimeError("simulated bind preparation failure")

    PrivateSocketPath.prepare_service_for_bind = _bind_failure
elif _mode != "normal":
    raise RuntimeError("unknown test daemon mode")

raise SystemExit(child.main())
