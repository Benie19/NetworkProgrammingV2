import struct
import socket
import pickle
import threading
import time
from collections import defaultdict
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Protocol.KDF import PBKDF2
except Exception:
    AES = None

# Simple framed protocol helpers
FRAME_HDR = struct.Struct('>I')


def send_frame(sock, data: bytes):
    sock.sendall(FRAME_HDR.pack(len(data)) + data)


def recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('socket closed')
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock):
    hdr = recv_exact(sock, FRAME_HDR.size)
    (length,) = FRAME_HDR.unpack(hdr)
    return recv_exact(sock, length)


def derive_key(passphrase: str) -> bytes:
    if AES is None:
        return b'\x00' * 32
    return PBKDF2(passphrase, b'salt-long-distance', dkLen=32, count=100_000)


def encrypt_blob(key: bytes, plaintext: bytes) -> bytes:
    if AES is None:
        return plaintext
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ct


def decrypt_blob(key: bytes, blob: bytes) -> bytes:
    if AES is None:
        return blob
    nonce = blob[:12]
    tag = blob[12:28]
    ct = blob[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


class RelayNode:
    def __init__(self, host='0.0.0.0', port=9000, passphrase='demo', neighbors=None, bandwidth_kbps=0):
        self.host = host
        self.port = port
        self.store = defaultdict(lambda: {'shards': {}, 'meta': None})
        self.lock = threading.Lock()
        self.key = derive_key(passphrase)
        self.neighbors = neighbors or []  # list of (host, port)
        self.bandwidth_kbps = bandwidth_kbps
        self.bytes_sent = 0
        self.window_start = time.time()

    def start(self):
        t = threading.Thread(target=self._bandwidth_window_thread, daemon=True)
        t.start()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(8)
        print(f'Relay listening on {self.host}:{self.port} (neighbors={self.neighbors})')
        try:
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_conn, args=(conn, addr), daemon=True).start()
        finally:
            s.close()

    def _bandwidth_window_thread(self):
        while True:
            time.sleep(1)
            with self.lock:
                self.bytes_sent = 0
                self.window_start = time.time()

    def handle_conn(self, conn: socket.socket, addr):
        try:
            frame = recv_frame(conn)
            packet = pickle.loads(frame)
            ptype = packet.get('type')
            if ptype == 'store_shard':
                self._handle_store(packet)
            elif ptype == 'fetch':
                self._handle_fetch(conn, packet)
        except ConnectionError:
            pass
        except Exception as e:
            print('Error handling conn:', e)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _handle_store(self, packet: dict):
        msg_id = packet['msg_id']
        shard_index = packet['shard_index']
        total_shards = packet['total_shards']
        priority = packet.get('priority', 1)
        dest = packet.get('dest')
        enc_blob = packet['payload']
        with self.lock:
            entry = self.store[msg_id]
            if entry['meta'] is None:
                entry['meta'] = {'total_shards': total_shards, 'priority': priority, 'dest': dest}
            entry['shards'][shard_index] = enc_blob
        print(f'Stored shard {shard_index}/{total_shards} for {msg_id[:8]} (dest={dest})')
        # optionally forward to neighbors to simulate multi-hop
        for nb in self.neighbors:
            threading.Thread(target=self._forward_to_neighbor, args=(nb, packet), daemon=True).start()

    def _forward_to_neighbor(self, neighbor, packet):
        priority = packet.get('priority', 1)
        size = len(packet.get('payload', b''))
        if self.bandwidth_kbps > 0 and priority > 0:
            kbps = self.bandwidth_kbps
            budget = kbps * 1000 / 8
            with self.lock:
                if self.bytes_sent + size > budget:
                    time.sleep(0.5)
        try:
            s = socket.create_connection(neighbor, timeout=3)
            send_frame(s, pickle.dumps(packet))
            s.close()
            with self.lock:
                self.bytes_sent += size
            print(f'Forwarded shard {packet["shard_index"]} of {packet["msg_id"][:8]} to {neighbor}')
        except Exception as e:
            print('Forward to neighbor failed:', e)

    def _handle_fetch(self, conn: socket.socket, packet: dict):
        dest = packet.get('dest')
        to_send = []
        with self.lock:
            for msg_id, rec in list(self.store.items()):
                meta = rec['meta']
                if not meta:
                    continue
                if meta.get('dest') == dest or dest is None:
                    for idx, blob in rec['shards'].items():
                        p = {'type': 'shard', 'msg_id': msg_id, 'shard_index': idx, 'total_shards': meta['total_shards'], 'priority': meta.get('priority',1), 'payload': blob}
                        to_send.append((meta.get('priority',1), msg_id, p))
                    del self.store[msg_id]
        to_send.sort(key=lambda x: x[0])
        for _, _, pkt in to_send:
            try:
                send_frame(conn, pickle.dumps(pkt))
                time.sleep(0.02)
            except Exception:
                break


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=9000)
    parser.add_argument('--pass', dest='pw', default='demo')
    parser.add_argument('--neighbor', action='append', help='neighbor as host:port')
    parser.add_argument('--bandwidth-kbps', type=int, default=0)
    args = parser.parse_args()
    neighbors = []
    if args.neighbor:
        for n in args.neighbor:
            h, p = n.split(':')
            neighbors.append((h, int(p)))
    node = RelayNode(host=args.host, port=args.port, passphrase=args.pw, neighbors=neighbors, bandwidth_kbps=args.bandwidth_kbps)
    node.start()