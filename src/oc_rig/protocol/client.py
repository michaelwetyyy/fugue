"""Thin network client for the Rig daemon protocol."""

from __future__ import annotations

import socket
import uuid
from pathlib import Path
from typing import Any, Mapping

from oc_rig.daemon.security import PrivateSocketPath, SocketSecurityError
from oc_rig.protocol.framing import DEFAULT_MAX_FRAME_BYTES, receive_frame, send_frame
from oc_rig.protocol.messages import ProtocolError, Request, Response


class RigClientError(RuntimeError):
    """A daemon request failed or its response could not be trusted."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class RigClient:
    """Issue one correlated request per private Unix-socket connection."""

    def __init__(
        self,
        socket_path: Path,
        *,
        approved_root: Path | None = None,
        service_uid: int | None = None,
        client_gid: int | None = None,
        identity_profile: str | None = None,
        timeout: float = 5.0,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
    ):
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.address = PrivateSocketPath(
            socket_path=socket_path,
            approved_root=approved_root or socket_path.parent,
        )
        self.timeout = timeout
        self.max_frame_bytes = max_frame_bytes
        self.service_uid = service_uid
        self.client_gid = client_gid
        if identity_profile not in {None, "dedicated-service", "local-user"}:
            raise ValueError("identity_profile is invalid")
        if identity_profile == "local-user" and (
            service_uid is not None or client_gid is not None
        ):
            raise ValueError("local-user profile does not accept service identity fields")
        if identity_profile in {None, "dedicated-service"} and (
            service_uid is None or client_gid is None
        ):
            raise ValueError(
                "dedicated-service profile requires service UID and client GID; "
                "local-user must be selected explicitly"
            )
        self.identity_profile = identity_profile or "dedicated-service"

    def call(
        self,
        operation: str,
        params: Mapping[str, Any] | None = None,
        *,
        request_id: str | None = None,
        idempotency_id: str | None = None,
    ) -> Mapping[str, Any]:
        request = Request(
            request_id=request_id or uuid.uuid4().hex,
            idempotency_id=idempotency_id or uuid.uuid4().hex,
            operation=operation,
            params=dict(params or {}),
        )
        try:
            socket_path = self.address.validate_for_connect(
                self.service_uid,
                self.client_gid,
                self.identity_profile,
            )
        except SocketSecurityError as error:
            raise RigClientError("socket_security", str(error)) from error
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(self.timeout)
            connection.connect(str(socket_path))
            send_frame(connection, request.encode(), max_bytes=self.max_frame_bytes)
            payload = receive_frame(connection, max_bytes=self.max_frame_bytes)
        try:
            response = Response.decode(payload)
        except ProtocolError as error:
            raise RigClientError(error.code, "daemon returned an invalid response") from error
        if (
            not response.ok
            and response.request_id is None
            and response.idempotency_id is None
        ):
            assert response.error is not None
            raise RigClientError(response.error["code"], response.error["message"])
        if response.request_id != request.request_id:
            raise RigClientError("correlation_mismatch", "response request ID did not match")
        if response.idempotency_id != request.idempotency_id:
            raise RigClientError("correlation_mismatch", "response idempotency ID did not match")
        if not response.ok:
            assert response.error is not None
            raise RigClientError(response.error["code"], response.error["message"])
        assert response.result is not None
        return response.result
