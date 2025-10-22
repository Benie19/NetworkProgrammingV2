import socket
import time
import pickle
import threading
import hashlib
import os
import uuid
from collections import defaultdict
from queue import Queue
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# Simple persistent log file (append-only)
LOG_FILE = os.path.join(os.path.dirname(__file__), 'mwrs.log')

# Encryption key (demo static - change for real use)
PASSWORD = b"mars-relay-key"
SALT = b"mars-salt"
KEY = PBKDF2(PASSWORD, SALT, dkLen=32, count=100_000)


def log_event(ev: str):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{ts}] {ev}\n"
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(line)
    print(line, end='')


def aes_decrypt(key: bytes, blob: bytes) -> bytes:
    iv = blob[:16]
    tag = blob[16:32]
    ciphertext = blob[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return iv + tag + ciphertext


def compute_checksum(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# per-destination queues with priority
message_store = defaultdict(lambda: {'urgent': [], 'normal': []})
store_lock = threading.Lock()


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


def forward_to_next_hop(msg):
    route = msg.get('route')
    if not route:
        return False
    next_hop = route.pop(0)
    try:
        with socket.create_connection(next_hop, timeout=5) as s:
            send_msg(s, msg)
        log_event(f"Forwarded {msg['id']} to {next_hop}")
        return True
    except Exception as e:
        log_event(f"Forward fail {msg['id']} -> {next_hop}: {e}")
        route.insert(0, next_hop)
        return False


def handle_client(conn, addr):
    try:
        msg = recv_msg(conn)
        if msg is None:
            return
        status = msg.get('status')
        if status == 'store':
            # validate required fields
            dest = msg.get('destination')
            if not dest:
                send_msg(conn, {'status': 'nack', 'reason': 'no_destination'})
                return

            # decrypt to validate checksum, keep encrypted payload
            payload = msg.get('payload')
            try:
                plaintext = aes_decrypt(KEY, payload)
            except Exception as e:
                send_msg(conn, {'status': 'nack', 'reason': 'decrypt_failed'})
                log_event(f"Decrypt failed from {addr}: {e}")
                return

            if compute_checksum(plaintext) != msg.get('checksum'):
                send_msg(conn, {'status': 'nack', 'reason': 'checksum_mismatch'})
                log_event(f"Checksum mismatch id={msg.get('id')} from {addr}")
                return

            # attempt multi-hop forward
            if msg.get('route'):
                if forward_to_next_hop(msg):
                    send_msg(conn, {'status': 'forwarded'})
                    return

            # store locally (priority)
            urgent = bool(msg.get('urgent'))
            with store_lock:
                if urgent:
                    message_store[dest]['urgent'].append(msg)
                else:
                    message_store[dest]['normal'].append(msg)
            send_msg(conn, {'status': 'stored'})
            log_event(f"Stored id={msg.get('id')} dest={dest} urgent={urgent}")

        elif status == 'fetch':
            dest = msg.get('destination')
            if not dest:
                send_msg(conn, {'status': 'nack', 'reason': 'no_destination'})
                return
            with store_lock:
                urgent_msgs = message_store[dest]['urgent'][:]
                normal_msgs = message_store[dest]['normal'][:]
                message_store[dest]['urgent'].clear()
                message_store[dest]['normal'].clear()

            for m in urgent_msgs + normal_msgs:
                send_msg(conn, m)
                time.sleep(0.1)
            send_msg(conn, {'status': 'done'})
            log_event(f"Delivered {len(urgent_msgs)+len(normal_msgs)} to {dest}")
        else:
            send_msg(conn, {'status': 'error', 'reason': 'unknown_status'})
    except Exception as e:
        log_event(f"Error handling client {addr}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def relay_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 6000))
    s.listen(10)
    log_event('MWRS Relay Node started on 0.0.0.0:6000')
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()


if __name__ == '__main__':
    relay_server()