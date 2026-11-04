"""Bounded, authenticated localhost HTTP/SSE client for OpenCode.

The client has no environment or ``HOME`` discovery.  Every authority-bearing
value is supplied by an already validated :class:`OpenCodeClientConfig`.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import time
from dataclasses import dataclass, field
from threading import Event, Timer
from typing import Any, Iterator, Mapping
from urllib.parse import quote, urlsplit

from oc_rig.opencode_authority import (
    OpenCodeAuthorityInvalid,
    REVIEW_AGENT_DESCRIPTION,
    REVIEW_AGENT_NAME,
    REVIEW_AGENT_PROMPT,
    automated_backend_authority,
)


MAX_REQUEST_BYTES = 64 * 1024
MAX_PROMPT_BYTES = 48 * 1024
MAX_RESPONSE_BYTES = 256 * 1024
MAX_MESSAGE_RESPONSE_BYTES = 512 * 1024
MAX_SSE_LINE_BYTES = 64 * 1024
MAX_SSE_EVENT_BYTES = 256 * 1024
CONNECT_TIMEOUT_SECONDS = 2.0
REQUEST_TIMEOUT_SECONDS = 8.0
SSE_READ_TIMEOUT_SECONDS = 30.0
MAX_SSE_RECONNECTS = 3

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
MAX_TOOL_IDS = 512
class OpenCodeConfigError(ValueError):
    """A stable, non-secret configuration failure."""


class OpenCodeClientError(RuntimeError):
    """A redacted HTTP failure with a transport certainty classification."""

    __slots__ = ("code", "delivery_unknown")

    def __init__(self, code: str, *, delivery_unknown: bool = False):
        super().__init__(code)
        self.code = code
        self.delivery_unknown = delivery_unknown


class SSEProtocolError(OpenCodeClientError):
    pass


@dataclass(frozen=True, slots=True)
class OpenCodeAuth:
    kind: str
    username: str | None
    secret: str = field(repr=False)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("OpenCodeAuth is sealed")

    def __post_init__(self) -> None:
        try:
            secret_size = len(self.secret.encode("utf-8"))
            username_utf8 = (
                self.username.encode("utf-8") if self.username is not None else b""
            )
        except (AttributeError, UnicodeError):
            raise OpenCodeConfigError("auth_invalid") from None
        if (
            self.kind not in {"bearer", "basic"}
            or not 16 <= secret_size <= 4096
            or any(character in self.secret for character in "\r\n\x00")
            or (self.kind == "bearer" and self.username is not None)
            or (
                self.kind == "basic"
                and (
                    type(self.username) is not str
                    or not 1 <= len(self.username) <= 128
                    or not username_utf8
                    or any(character in self.username for character in ":\r\n\x00")
                )
            )
        ):
            raise OpenCodeConfigError("auth_invalid")

    @classmethod
    def bearer(cls, secret: object) -> "OpenCodeAuth":
        return cls("bearer", None, secret)  # type: ignore[arg-type]

    @classmethod
    def basic(cls, username: object, secret: object) -> "OpenCodeAuth":
        return cls("basic", username, secret)  # type: ignore[arg-type]

    def header(self) -> str:
        if self.kind == "bearer":
            return f"Bearer {self.secret}"
        material = f"{self.username}:{self.secret}".encode("utf-8")
        return "Basic " + base64.b64encode(material).decode("ascii")


@dataclass(frozen=True, slots=True)
class OpenCodeClientConfig:
    host: str
    port: int
    auth: OpenCodeAuth

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("OpenCodeClientConfig is sealed")

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError:
            raise OpenCodeConfigError("endpoint_not_allowlisted") from None
        if (
            address
            not in {ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")}
            or type(self.port) is not int
            or not 1 <= self.port <= 65535
            or type(self.auth) is not OpenCodeAuth
        ):
            raise OpenCodeConfigError("endpoint_invalid")

    @classmethod
    def explicit(cls, endpoint: str, auth: OpenCodeAuth) -> "OpenCodeClientConfig":
        if not isinstance(endpoint, str):
            raise OpenCodeConfigError("endpoint_invalid")
        try:
            parsed = urlsplit(endpoint)
        except ValueError:
            raise OpenCodeConfigError("endpoint_invalid") from None
        try:
            port = parsed.port
        except ValueError:
            raise OpenCodeConfigError("endpoint_invalid") from None
        if (
            parsed.scheme != "http"
            or parsed.hostname is None
            or port is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise OpenCodeConfigError("endpoint_invalid")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            raise OpenCodeConfigError("endpoint_not_allowlisted") from None
        if address not in {ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")}:
            raise OpenCodeConfigError("endpoint_not_allowlisted")
        if not 1 <= port <= 65535:
            raise OpenCodeConfigError("endpoint_invalid")
        if type(auth) is not OpenCodeAuth:
            raise OpenCodeConfigError("auth_invalid")
        return cls(parsed.hostname, port, auth)


@dataclass(frozen=True, slots=True)
class SSEEvent:
    event_id: str | None
    event: str | None
    data: str

    def json(self) -> Mapping[str, Any]:
        try:
            value = json.loads(self.data)
        except (json.JSONDecodeError, UnicodeError):
            raise SSEProtocolError("sse_data_invalid") from None
        if type(value) is not dict:
            raise SSEProtocolError("sse_data_invalid")
        return value


def validate_identifier(value: object, field: str = "identifier") -> str:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value):
        raise OpenCodeClientError(f"{field}_invalid")
    return value


class _Deadline:
    """Monotonic wall deadline that also interrupts trickling socket reads."""

    __slots__ = ("connection", "expires_at", "expired", "socket", "timer")

    def __init__(
        self,
        connection: http.client.HTTPConnection,
        seconds: float,
        sock: socket.socket | None = None,
    ):
        self.connection = connection
        self.expires_at = time.monotonic() + seconds
        self.expired = Event()
        self.socket = sock
        self.timer = Timer(seconds, self._expire)
        self.timer.daemon = True
        self.timer.start()

    def _expire(self) -> None:
        self.expired.set()
        sock = self.socket or self.connection.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.connection.close()

    def remaining(self) -> float:
        remaining = self.expires_at - time.monotonic()
        if remaining <= 0 or self.expired.is_set():
            raise OpenCodeClientError("request_deadline_exceeded")
        return remaining

    def close(self) -> None:
        self.timer.cancel()
        self.timer.join()


def _remaining(deadline: _Deadline, *, delivery_unknown: bool = False) -> float:
    try:
        return deadline.remaining()
    except OpenCodeClientError:
        raise OpenCodeClientError(
            "request_deadline_exceeded", delivery_unknown=delivery_unknown
        ) from None


class OpenCodeClient:
    """Dependency-free REST client with explicit send-intent accounting."""

    __slots__ = ("_authorization", "_host", "_port")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("OpenCodeClient is sealed")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("OpenCodeClient is immutable")

    def __init__(self, config: OpenCodeClientConfig):
        if type(config) is not OpenCodeClientConfig:
            raise TypeError("validated OpenCodeClientConfig required")
        object.__setattr__(self, "_host", config.host)
        object.__setattr__(self, "_port", config.port)
        object.__setattr__(self, "_authorization", config.auth.header())

    def _connection(self, timeout: float) -> http.client.HTTPConnection:
        return http.client.HTTPConnection(self._host, self._port, timeout=timeout)

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
        mutation: bool = False,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> tuple[int, bytes, Mapping[str, str]]:
        encoded = b""
        if body is not None:
            try:
                encoded = json.dumps(
                    dict(body), sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            except (TypeError, ValueError, UnicodeError):
                raise OpenCodeClientError("request_invalid") from None
        if len(encoded) > MAX_REQUEST_BYTES:
            raise OpenCodeClientError("request_too_large")
        headers = {
            "Accept": "application/json",
            "Authorization": self._authorization,
            "Connection": "close",
            "Content-Type": "application/json",
        }
        if idempotency_key is not None:
            headers["Idempotency-Key"] = validate_identifier(
                idempotency_key, "idempotency_key"
            )
        connection = self._connection(CONNECT_TIMEOUT_SECONDS)
        deadline = _Deadline(connection, REQUEST_TIMEOUT_SECONDS)
        send_started = False
        try:
            try:
                connection.timeout = min(CONNECT_TIMEOUT_SECONDS, _remaining(deadline))
                connection.connect()
            except (OSError, socket.timeout, http.client.HTTPException) as error:
                if deadline.expired.is_set():
                    raise OpenCodeClientError(
                        "request_deadline_exceeded",
                        delivery_unknown=mutation and send_started,
                    ) from None
                raise OpenCodeClientError("connection_failed") from error
            if connection.sock is not None:
                deadline.socket = connection.sock
                connection.sock.settimeout(_remaining(deadline))
            connection.putrequest(method, path, skip_accept_encoding=True)
            for key, value in headers.items():
                connection.putheader(key, value)
            connection.putheader("Content-Length", str(len(encoded)))
            send_started = True
            connection.endheaders(encoded)
            if connection.sock is not None:
                connection.sock.settimeout(
                    _remaining(deadline, delivery_unknown=mutation and send_started)
                )
            response = connection.getresponse()
            if connection.sock is not None:
                connection.sock.settimeout(
                    _remaining(deadline, delivery_unknown=mutation and send_started)
                )
            payload = response.read(max_response_bytes + 1)
            if deadline.expired.is_set():
                raise OpenCodeClientError(
                    "request_deadline_exceeded",
                    delivery_unknown=mutation and send_started,
                )
            if len(payload) > max_response_bytes:
                raise OpenCodeClientError(
                    "response_too_large", delivery_unknown=mutation and send_started
                )
            response_headers = {key.lower(): value for key, value in response.getheaders()}
            return response.status, payload, response_headers
        except OpenCodeClientError:
            raise
        except (OSError, socket.timeout, http.client.HTTPException) as error:
            if deadline.expired.is_set():
                raise OpenCodeClientError(
                    "request_deadline_exceeded",
                    delivery_unknown=mutation and send_started,
                ) from None
            raise OpenCodeClientError(
                "request_failed", delivery_unknown=mutation and send_started
            ) from error
        finally:
            connection.close()
            deadline.close()

    @staticmethod
    def _json(payload: bytes, code: str) -> Any:
        try:
            return json.loads(payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeError):
            raise OpenCodeClientError(code) from None

    def list_sessions(self) -> list[Mapping[str, Any]]:
        status, payload, _ = self._request("GET", "/session")
        if status != 200:
            raise OpenCodeClientError("sessions_unavailable")
        value = self._json(payload, "sessions_invalid")
        if type(value) is not list or any(type(item) is not dict for item in value):
            raise OpenCodeClientError("sessions_invalid")
        return value

    def create_session(self, *, title: str, idempotency_key: str) -> str:
        """Create one isolated session and return only its validated ID."""

        status, payload, _ = self._request(
            "POST",
            "/session",
            body={"title": validate_identifier(title, "session_title")},
            idempotency_key=idempotency_key,
            mutation=True,
        )
        if status not in {200, 201}:
            raise OpenCodeClientError(
                "session_create_failed", delivery_unknown=status >= 500
            )
        value = self._json(payload, "session_create_invalid")
        if type(value) is not dict:
            raise OpenCodeClientError("session_create_invalid")
        return validate_identifier(value.get("id"), "session_id")

    def session_status(self) -> Mapping[str, Any]:
        status, payload, _ = self._request("GET", "/session/status")
        if status != 200:
            raise OpenCodeClientError("status_unavailable")
        value = self._json(payload, "status_invalid")
        if type(value) is not dict:
            raise OpenCodeClientError("status_invalid")
        return value

    def tool_ids(self) -> tuple[str, ...]:
        status, payload, _ = self._request("GET", "/experimental/tool/ids")
        if status != 200:
            raise OpenCodeClientError("tool_roster_unavailable")
        value = self._json(payload, "tool_roster_invalid")
        if (
            type(value) is not list
            or not value
            or len(value) > MAX_TOOL_IDS
            or any(type(item) is not str for item in value)
        ):
            raise OpenCodeClientError("tool_roster_invalid")
        try:
            validated = tuple(validate_identifier(item, "tool_id") for item in value)
        except OpenCodeClientError:
            raise OpenCodeClientError("tool_roster_invalid") from None
        if len(set(validated)) != len(validated):
            raise OpenCodeClientError("tool_roster_invalid")
        return tuple(sorted(validated))

    def review_agent_identity(self) -> str:
        agent_status, agent_payload, _ = self._request("GET", "/agent")
        config_status, config_payload, _ = self._request("GET", "/config")
        if agent_status != 200 or config_status != 200:
            raise OpenCodeClientError("review_agent_unavailable")
        agents = self._json(agent_payload, "review_agent_invalid")
        config = self._json(config_payload, "review_agent_invalid")
        try:
            return automated_backend_authority(config, agents)
        except OpenCodeAuthorityInvalid:
            raise OpenCodeClientError("review_agent_invalid")

    def messages(self, session_id: str, *, limit: int) -> list[Mapping[str, Any]]:
        session = quote(validate_identifier(session_id, "session_id"), safe="")
        if type(limit) is not int or not 1 <= limit <= 16:
            raise OpenCodeClientError("message_limit_invalid")
        status, payload, _ = self._request(
            "GET",
            f"/session/{session}/message?limit={limit}",
            max_response_bytes=MAX_MESSAGE_RESPONSE_BYTES,
        )
        if status != 200:
            raise OpenCodeClientError("messages_unavailable")
        value = self._json(payload, "messages_invalid")
        if type(value) is not list or any(type(item) is not dict for item in value):
            raise OpenCodeClientError("messages_invalid")
        return value

    def todos(self, session_id: str) -> list[Mapping[str, Any]]:
        session = quote(validate_identifier(session_id, "session_id"), safe="")
        status, payload, _ = self._request("GET", f"/session/{session}/todo")
        if status != 200:
            raise OpenCodeClientError("todos_unavailable")
        value = self._json(payload, "todos_invalid")
        if type(value) is not list or any(type(item) is not dict for item in value):
            raise OpenCodeClientError("todos_invalid")
        return value

    def prompt_async(
        self,
        session_id: str,
        body: Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> None:
        session = quote(validate_identifier(session_id, "session_id"), safe="")
        status, _payload, _ = self._request(
            "POST",
            f"/session/{session}/prompt_async",
            body=body,
            idempotency_key=idempotency_key,
            mutation=True,
        )
        if status not in {200, 202, 204}:
            raise OpenCodeClientError(
                "prompt_rejected", delivery_unknown=status >= 500
            )

    def abort(self, session_id: str, *, idempotency_key: str) -> bool:
        session = quote(validate_identifier(session_id, "session_id"), safe="")
        status, payload, _ = self._request(
            "POST",
            f"/session/{session}/abort",
            body={},
            idempotency_key=idempotency_key,
            mutation=True,
        )
        if status != 200:
            raise OpenCodeClientError("abort_failed", delivery_unknown=status >= 500)
        value = self._json(payload, "abort_invalid")
        if type(value) is not bool:
            raise OpenCodeClientError("abort_invalid")
        return value

    def delete(self, session_id: str, *, idempotency_key: str) -> str:
        session = quote(validate_identifier(session_id, "session_id"), safe="")
        status, payload, _ = self._request(
            "DELETE",
            f"/session/{session}",
            body={},
            idempotency_key=idempotency_key,
            mutation=True,
        )
        if status == 404:
            return "absent"
        if status != 200:
            raise OpenCodeClientError("delete_failed", delivery_unknown=status >= 500)
        value = self._json(payload, "delete_invalid")
        if type(value) is not bool:
            raise OpenCodeClientError("delete_invalid")
        return "deleted" if value else "refused"

    def event_stream(
        self,
        cancellation: Event,
    ) -> Iterator[SSEEvent]:
        """Yield one installed-server SSE connection without replay headers."""

        headers = {
            "Accept": "text/event-stream",
            "Authorization": self._authorization,
            "Cache-Control": "no-cache",
        }
        connection = self._connection(CONNECT_TIMEOUT_SECONDS)
        deadline = _Deadline(connection, REQUEST_TIMEOUT_SECONDS)
        try:
            try:
                connection.timeout = min(CONNECT_TIMEOUT_SECONDS, _remaining(deadline))
                connection.connect()
                if connection.sock is not None:
                    deadline.socket = connection.sock
                    connection.sock.settimeout(_remaining(deadline))
                connection.request("GET", "/event", headers=headers)
                if connection.sock is not None:
                    connection.sock.settimeout(_remaining(deadline))
                response = connection.getresponse()
            except (OSError, socket.timeout, http.client.HTTPException) as error:
                if deadline.expired.is_set():
                    raise OpenCodeClientError("request_deadline_exceeded") from None
                raise OpenCodeClientError("sse_connection_failed") from error
            finally:
                deadline.close()
            content_type = response.getheader("Content-Type", "").split(";", 1)[0]
            if response.status != 200 or content_type != "text/event-stream":
                raise OpenCodeClientError("sse_rejected")
            yield from _parse_sse(response, cancellation, connection, deadline.socket)
        finally:
            connection.close()


def _parse_sse(
    response: http.client.HTTPResponse,
    cancellation: Event,
    connection: http.client.HTTPConnection | None = None,
    stream_socket: socket.socket | None = None,
) -> Iterator[SSEEvent]:
    event_name: str | None = None
    data: list[str] = []
    event_size = 0
    while not cancellation.is_set():
        line_deadline = None
        line_timed_out = False
        try:
            line_deadline = (
                _Deadline(connection, SSE_READ_TIMEOUT_SECONDS, stream_socket)
                if connection is not None
                else None
            )
            raw = response.readline(MAX_SSE_LINE_BYTES + 1)
        except (OSError, socket.timeout, http.client.HTTPException):
            raise OpenCodeClientError("sse_disconnected") from None
        finally:
            if line_deadline is not None:
                line_timed_out = line_deadline.expired.is_set()
                line_deadline.close()
        if line_timed_out:
            raise OpenCodeClientError("sse_line_deadline_exceeded")
        if not raw:
            if data or event_name is not None:
                raise SSEProtocolError("sse_truncated")
            return
        if len(raw) > MAX_SSE_LINE_BYTES:
            raise SSEProtocolError("sse_line_too_large")
        try:
            line = raw.decode("utf-8").rstrip("\r\n")
        except UnicodeError:
            raise SSEProtocolError("sse_encoding_invalid") from None
        if line == "":
            if data:
                yield SSEEvent(None, event_name, "\n".join(data))
            event_name = None
            data = []
            event_size = 0
            continue
        if line.startswith(":"):
            continue
        field, separator, value = line.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if field == "id":
            raise SSEProtocolError("backend_event_stream_incompatible")
        elif field == "event":
            raise SSEProtocolError("backend_event_stream_incompatible")
        elif field == "data":
            if data:
                raise SSEProtocolError("backend_event_stream_incompatible")
            event_size += len(value.encode("utf-8"))
            if event_size > MAX_SSE_EVENT_BYTES:
                raise SSEProtocolError("sse_event_too_large")
            data.append(value)
        else:
            raise SSEProtocolError("backend_event_stream_incompatible")
