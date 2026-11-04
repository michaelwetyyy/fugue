"""Length-prefixed framing with a small, fixed upper bound."""

from __future__ import annotations

import socket
import struct


DEFAULT_MAX_FRAME_BYTES = 64 * 1024
_HEADER = struct.Struct("!I")


class FrameError(ValueError):
    """A peer sent an invalid or incomplete frame."""


class FrameTooLarge(FrameError):
    """A peer declared or supplied a frame above the configured limit."""


class IncompleteFrame(FrameError):
    """A peer closed the connection in the middle of a frame."""


def _receive_exact(connection: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise IncompleteFrame("connection closed before the frame was complete")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def receive_frame(
    connection: socket.socket,
    *,
    max_bytes: int = DEFAULT_MAX_FRAME_BYTES,
) -> bytes:
    """Receive one complete frame, handling arbitrary stream fragmentation."""
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    header = _receive_exact(connection, _HEADER.size)
    (length,) = _HEADER.unpack(header)
    if length == 0:
        raise FrameError("empty frames are forbidden")
    if length > max_bytes:
        raise FrameTooLarge("declared frame exceeds the protocol limit")
    return _receive_exact(connection, length)


def send_frame(
    connection: socket.socket,
    payload: bytes,
    *,
    max_bytes: int = DEFAULT_MAX_FRAME_BYTES,
) -> None:
    """Send one frame after enforcing the same bound used by the receiver."""
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if not payload:
        raise FrameError("empty frames are forbidden")
    if len(payload) > max_bytes:
        raise FrameTooLarge("frame exceeds the protocol limit")
    connection.sendall(_HEADER.pack(len(payload)) + payload)
