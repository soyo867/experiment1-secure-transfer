"""SFT/1 framing: 20-byte network-order header, JSON metadata, binary data.

TCP is a byte stream: exact reads and sendall deliberately handle partial I/O.
Frames are bounded before allocation, and reads have an absolute deadline.
"""
from dataclasses import dataclass
import json
import socket
import struct
import time

MAGIC = b"SFT1"
VERSION = 1
REQUEST = 1
RESPONSE = 2
HEADER = struct.Struct("!4sBBHIII")
MAX_JSON = 16 * 1024
CHUNK_SIZE = 64 * 1024
MAX_PAYLOAD = CHUNK_SIZE


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class Frame:
    request_id: int
    metadata: dict
    payload: bytes
    frame_type: int


def _exact(sock, count, deadline):
    chunks = bytearray()
    while len(chunks) < count:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Frame read deadline exceeded")
            sock.settimeout(remaining)
        data = sock.recv(count - len(chunks))
        if not data:
            raise EOFError("Peer closed the connection")
        chunks.extend(data)
    return bytes(chunks)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("Duplicate JSON object key")
        result[key] = value
    return result


def recv_frame(sock, timeout=30.0):
    deadline = None if timeout is None else time.monotonic() + timeout
    original_timeout = sock.gettimeout()
    try:
        header = _exact(sock, HEADER.size, deadline)
        magic, version, kind, flags, request_id, json_length, payload_length = HEADER.unpack(header)
        if magic != MAGIC or version != VERSION or flags or kind not in (REQUEST, RESPONSE):
            raise ProtocolError("Invalid protocol magic/version/type/flags")
        if request_id == 0 or not 2 <= json_length <= MAX_JSON or payload_length > MAX_PAYLOAD:
            raise ProtocolError("Invalid request ID or frame length")
        raw = _exact(sock, json_length, deadline)
        try:
            metadata = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                                  parse_constant=lambda x: (_ for _ in ()).throw(ProtocolError("Non-finite JSON number")))
        except (UnicodeError, ValueError, RecursionError) as exc:
            raise ProtocolError("Invalid JSON metadata") from exc
        if not isinstance(metadata, dict):
            raise ProtocolError("JSON metadata must be an object")
        payload = _exact(sock, payload_length, deadline)
        return Frame(request_id, metadata, payload, kind)
    finally:
        sock.settimeout(original_timeout)


def send_frame(sock, request_id, metadata, payload=b"", frame_type=REQUEST):
    if type(request_id) is not int or not 0 < request_id <= 0xFFFFFFFF:
        raise ProtocolError("Request ID outside uint32 range")
    if frame_type not in (REQUEST, RESPONSE) or not isinstance(metadata, dict):
        raise ProtocolError("Invalid frame type or metadata")
    try:
        raw = json.dumps(metadata, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError) as exc:
        raise ProtocolError("Metadata cannot be encoded") from exc
    payload = bytes(payload)
    if len(raw) > MAX_JSON or len(payload) > MAX_PAYLOAD:
        raise ProtocolError("Frame exceeds configured bounds")
    sock.sendall(HEADER.pack(MAGIC, VERSION, frame_type, 0, request_id, len(raw), len(payload)) + raw + payload)


def keep_alive(sock):
    """Kernel TCP keep-alive complements application PING/PONG heartbeats."""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    for name, value in (("TCP_KEEPIDLE", 30), ("TCP_KEEPINTVL", 10), ("TCP_KEEPCNT", 3)):
        option = getattr(socket, name, None)
        if option is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, option, value)
            except OSError:
                pass
    if hasattr(socket, "SIO_KEEPALIVE_VALS"):
        try:
            sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 30000, 10000))
        except OSError:
            pass
