"""Strict request and response schemas for protocol version 1."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping


PROTOCOL_VERSION = 1
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_OPERATION = re.compile(r"[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*){0,7}\Z")


class ProtocolError(ValueError):
    """A message did not conform to the public wire schema."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _no_constants(value: str) -> None:
    raise ProtocolError("malformed_json", f"non-finite JSON number is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("malformed_json", "duplicate JSON object keys are forbidden")
        result[key] = value
    return result


def _load_object(payload: bytes) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtocolError("malformed_json", "message is not valid UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_no_constants,
        )
    except ProtocolError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        raise ProtocolError("malformed_json", "message is not valid JSON") from error
    if not isinstance(value, dict):
        raise ProtocolError("invalid_schema", "message must be a JSON object")
    return value


def _exact_fields(value: Mapping[str, Any], required: set[str]) -> None:
    missing = required - value.keys()
    unknown = value.keys() - required
    if missing:
        raise ProtocolError("invalid_schema", "message is missing required fields")
    if unknown:
        raise ProtocolError("invalid_schema", "message has unknown fields")


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ProtocolError("invalid_schema", f"{field} is not a valid identifier")
    return value


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise ProtocolError("invalid_schema", "message contains a non-JSON value") from error


@dataclass(frozen=True, slots=True)
class Request:
    request_id: str
    idempotency_id: str
    operation: str
    params: Mapping[str, Any]
    version: int = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        _identifier(self.request_id, "request_id")
        _identifier(self.idempotency_id, "idempotency_id")
        if type(self.version) is not int:
            raise ProtocolError("invalid_schema", "version must be an integer")
        if self.version != PROTOCOL_VERSION:
            raise ProtocolError("unsupported_version", "protocol version is not supported")
        if not isinstance(self.operation, str) or not _OPERATION.fullmatch(self.operation):
            raise ProtocolError("invalid_schema", "operation is invalid")
        if not isinstance(self.params, Mapping):
            raise ProtocolError("invalid_schema", "params must be an object")
        _json_bytes(dict(self.params))

    def encode(self) -> bytes:
        return _json_bytes(
            {
                "idempotency_id": self.idempotency_id,
                "message_type": "request",
                "operation": self.operation,
                "params": dict(self.params),
                "request_id": self.request_id,
                "version": self.version,
            }
        )

    @classmethod
    def decode(cls, payload: bytes) -> "Request":
        value = _load_object(payload)
        fields = {
            "version",
            "message_type",
            "request_id",
            "idempotency_id",
            "operation",
            "params",
        }
        _exact_fields(value, fields)
        if value["message_type"] != "request":
            raise ProtocolError("invalid_schema", "message_type must be request")
        return cls(
            version=value["version"],
            request_id=value["request_id"],
            idempotency_id=value["idempotency_id"],
            operation=value["operation"],
            params=value["params"],
        )


@dataclass(frozen=True, slots=True)
class Response:
    request_id: str | None
    idempotency_id: str | None
    ok: bool
    result: Mapping[str, Any] | None = None
    error: Mapping[str, str] | None = None
    version: int = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        if self.request_id is not None:
            _identifier(self.request_id, "request_id")
        if self.idempotency_id is not None:
            _identifier(self.idempotency_id, "idempotency_id")
        if type(self.version) is not int or self.version != PROTOCOL_VERSION:
            raise ProtocolError("unsupported_version", "protocol version is not supported")
        if type(self.ok) is not bool:
            raise ProtocolError("invalid_schema", "ok must be a boolean")
        if self.ok:
            if not isinstance(self.result, Mapping) or self.error is not None:
                raise ProtocolError("invalid_schema", "successful response requires only result")
            _json_bytes(dict(self.result))
        else:
            if self.result is not None or not isinstance(self.error, Mapping):
                raise ProtocolError("invalid_schema", "error response requires only error")
            _exact_fields(self.error, {"code", "message"})
            _identifier(self.error["code"], "error.code")
            if not isinstance(self.error["message"], str) or len(self.error["message"]) > 500:
                raise ProtocolError("invalid_schema", "error.message is invalid")

    @classmethod
    def success(cls, request: Request, result: Mapping[str, Any]) -> "Response":
        return cls(request.request_id, request.idempotency_id, True, result=dict(result))

    @classmethod
    def failure(
        cls,
        request: Request | None,
        code: str,
        message: str,
    ) -> "Response":
        return cls(
            request.request_id if request else None,
            request.idempotency_id if request else None,
            False,
            error={"code": code, "message": message},
        )

    def encode(self) -> bytes:
        common: dict[str, Any] = {
            "idempotency_id": self.idempotency_id,
            "message_type": "response",
            "ok": self.ok,
            "request_id": self.request_id,
            "version": self.version,
        }
        common["result" if self.ok else "error"] = dict(
            self.result if self.ok else self.error or {}
        )
        return _json_bytes(common)

    @classmethod
    def decode(cls, payload: bytes) -> "Response":
        value = _load_object(payload)
        common = {
            "version",
            "message_type",
            "request_id",
            "idempotency_id",
            "ok",
        }
        if value.get("message_type") != "response":
            raise ProtocolError("invalid_schema", "message_type must be response")
        if value.get("ok") is True:
            _exact_fields(value, common | {"result"})
            return cls(
                value["request_id"],
                value["idempotency_id"],
                True,
                result=value["result"],
                version=value["version"],
            )
        _exact_fields(value, common | {"error"})
        return cls(
            value["request_id"],
            value["idempotency_id"],
            False,
            error=value["error"],
            version=value["version"],
        )
