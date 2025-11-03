import struct
import socket
import uuid
from typing import Tuple

FRAME_HDR = struct.Struct('>I')  # 4-byte length prefix
MSG_HDR = struct.Struct('>B B 16s H H I')

VERSION = 1

# compression flags
COMP_GZIP = 0
COMP_JPEG = 1
COMP_NONE = 2

def send_frame(sock: socket.socket, data: bytes) -> None:
    """Send length-prefixed frame over a TCP socket."""
    sock.sendall(FRAME_HDR.pack(len(data)) + data)

def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('socket closed while reading')
        buf.extend(chunk)
    return bytes(buf)

def recv_frame(sock: socket.socket) -> bytes:
    """Receive a single length-prefixed frame and return payload bytes."""
    hdr = recv_exact(sock, FRAME_HDR.size)
    (length,) = FRAME_HDR.unpack(hdr)
    return recv_exact(sock, length)

def pack_msg_header(flags: int, msg_id: uuid.UUID, total_shards: int, shard_index: int, orig_len: int) -> bytes:
    return MSG_HDR.pack(VERSION, flags & 0xFF, msg_id.bytes, total_shards, shard_index, orig_len)

def unpack_msg_header(data: bytes) -> Tuple[int, int, uuid.UUID, int, int, int]:
    """Unpack a header from bytes, return tuple: (version, flags, UUID, total_shards, shard_index, orig_len)"""
    if len(data) < MSG_HDR.size:
        raise ValueError('header too short')
    version, flags, msg_bytes, total_shards, shard_index, orig_len = MSG_HDR.unpack(data[:MSG_HDR.size])
    return version, flags, uuid.UUID(bytes=msg_bytes), total_shards, shard_index, orig_len
