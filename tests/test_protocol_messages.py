from __future__ import annotations

import socket
import struct
import threading
import unittest

from oc_rig.protocol.framing import FrameError, FrameTooLarge, receive_frame, send_frame
from oc_rig.protocol.messages import PROTOCOL_VERSION, ProtocolError, Request, Response


class ProtocolMessageTests(unittest.TestCase):
    def test_request_and_response_are_strict_and_correlated(self) -> None:
        request = Request("request-1", "retry-1", "health", {})
        self.assertEqual(Request.decode(request.encode()), request)
        response = Response.success(request, {"status": "ok"})
        decoded = Response.decode(response.encode())
        self.assertEqual(decoded.version, PROTOCOL_VERSION)
        self.assertEqual(decoded.request_id, request.request_id)
        self.assertEqual(decoded.idempotency_id, request.idempotency_id)
        self.assertEqual(decoded.result, {"status": "ok"})

    def test_unknown_duplicate_and_malformed_fields_are_rejected(self) -> None:
        valid = Request("request-1", "retry-1", "health", {}).encode()
        unknown = valid[:-1] + b',"extra":true}'
        duplicate = valid[:-1] + b',"params":{}}'
        for payload in (unknown, duplicate, b"not-json", b"[]", b"\xff"):
            with self.subTest(payload=payload):
                with self.assertRaises(ProtocolError):
                    Request.decode(payload)

    def test_unsupported_versions_and_missing_idempotency_are_rejected(self) -> None:
        unsupported = (
            b'{"idempotency_id":"retry-1","message_type":"request",'
            b'"operation":"health","params":{},"request_id":"request-1","version":2}'
        )
        missing = (
            b'{"message_type":"request","operation":"health","params":{},'
            b'"request_id":"request-1","version":1}'
        )
        with self.assertRaisesRegex(ProtocolError, "version"):
            Request.decode(unsupported)
        with self.assertRaisesRegex(ProtocolError, "missing required"):
            Request.decode(missing)


class FramingTests(unittest.TestCase):
    def test_partial_header_and_payload_reads_are_reassembled(self) -> None:
        receiver, sender = socket.socketpair()
        payload = Request("request-1", "retry-1", "health", {}).encode()

        def write_pieces() -> None:
            wire = struct.pack("!I", len(payload)) + payload
            for byte in wire:
                sender.sendall(bytes([byte]))
            sender.close()

        thread = threading.Thread(target=write_pieces)
        thread.start()
        try:
            self.assertEqual(receive_frame(receiver), payload)
        finally:
            receiver.close()
            thread.join()

    def test_empty_and_oversized_frames_are_rejected(self) -> None:
        receiver, sender = socket.socketpair()
        try:
            sender.sendall(struct.pack("!I", 0))
            with self.assertRaises(FrameError):
                receive_frame(receiver)
        finally:
            receiver.close()
            sender.close()
        receiver, sender = socket.socketpair()
        try:
            sender.sendall(struct.pack("!I", 9))
            with self.assertRaises(FrameTooLarge):
                receive_frame(receiver, max_bytes=8)
            with self.assertRaises(FrameTooLarge):
                send_frame(sender, b"123456789", max_bytes=8)
        finally:
            receiver.close()
            sender.close()


if __name__ == "__main__":
    unittest.main()
