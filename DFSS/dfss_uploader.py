import os
import sys
import socket
import pickle
import hashlib
import time
from pathlib import Path


def send_msg(conn, obj):
    data = pickle.dumps(obj)
    conn.sendall(len(data).to_bytes(4, 'big') + data)


def recv_msg(conn):
    len_b = conn.recv(4)
    if not len_b:
        return None
    total = int.from_bytes(len_b, 'big')
    chunks = bytearray()
    while len(chunks) < total:
        chunk = conn.recv(min(4096, total - len(chunks)))
        if not chunk:
            raise ConnectionError('socket closed')
        chunks.extend(chunk)
    return pickle.loads(bytes(chunks))


def compute_checksum(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def store_chunk(peer_host, peer_port, filename, index, total, payload, max_attempts=3):
    for attempt in range(1, max_attempts + 1):
        try:
            with socket.create_connection((peer_host, peer_port), timeout=5) as s:
                send_msg(s, {'type': 'store_chunk', 'filename': filename, 'index': index, 'total': total, 'payload': payload, 'checksum': compute_checksum(payload)})
                resp = recv_msg(s)
                return resp
        except Exception as e:
            print(f"Store attempt {attempt} failed for {filename}[{index}] -> {peer_host}:{peer_port}: {e}")
            time.sleep(0.5 * attempt)
    return {'status': 'failed'}


def split_and_upload(path: Path, peers, chunk_size=64 * 1024):
    filesize = path.stat().st_size
    total = (filesize + chunk_size - 1) // chunk_size
    print(f"Uploading {path.name} ({filesize} bytes) as {total} chunks to {len(peers)} peers")

    with open(path, 'rb') as f:
        index = 0
        peer_idx = 0
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            host, port = peers[peer_idx]
            resp = store_chunk(host, port, path.name, index, total, chunk)
            if resp and resp.get('status') == 'stored':
                print(f"Uploaded chunk {index} -> {host}:{port}")
            else:
                print(f"Failed to upload chunk {index} -> {host}:{port}")
            index += 1
            peer_idx = (peer_idx + 1) % len(peers)


def parse_peers(peers_str):
    out = []
    for item in peers_str.split(','):
        host, port = item.split(':')
        out.append((host, int(port)))
    return out


def main():
    if len(sys.argv) < 3:
        print("Usage: dfss_uploader.py <file> <peer1:port,peer2:port,...> [chunk_size]")
        return
    path = Path(sys.argv[1])
    peers = parse_peers(sys.argv[2])
    chunk_size = int(sys.argv[3]) if len(sys.argv) >= 4 else 64 * 1024
    split_and_upload(path, peers, chunk_size=chunk_size)


if __name__ == '__main__':
    main()
