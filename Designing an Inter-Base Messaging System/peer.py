import socket
import threading
import pickle
import time
import os
import hashlib
from collections import defaultdict
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# Simple IBMS peer (stores and forwards messages between bases)
# Log file (append-only)
LOG_FILE = os.path.join(os.path.dirname(__file__), 'ibms.log')

# Demo key (change in real use)
PASSWORD = b"ibms-demo-key"
SALT = b"ibms-salt"
KEY = PBKDF2(PASSWORD, SALT, dkLen=32, count=100_000)


def log_event(ev: str):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{ts}] {ev}\n"
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(line)
    print(line, end='')


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


# per-destination priority queues
message_store = defaultdict(lambda: {'urgent': [], 'normal': []})
store_lock = threading.Lock()


def forward_to_next_hop(msg):
    route = msg.get('route')
    if not route:
        return False
    next_hop = route.pop(0)
    try:
        with socket.create_connection(next_hop, timeout=5) as s:
            send_msg(s, msg)
        log_event(f"Forwarded {msg.get('id')} to {next_hop}")
        return True
    except Exception as e:
        log_event(f"Forward failed {msg.get('id')} -> {next_hop}: {e}")
        route.insert(0, next_hop)
        return False


def handle_client(conn, addr):
    try:
        msg = recv_msg(conn)
        if msg is None:
            return

        mtype = msg.get('type')
        if mtype == 'store_message':
            dest = msg.get('destination')
            if not dest:
                send_msg(conn, {'status': 'nack', 'reason': 'no_destination'})
                return

            payload = msg.get('payload')
            checksum = msg.get('checksum')
            # decrypt to validate checksum (keep encrypted stored)
            try:
                plaintext = aes_decrypt(KEY, payload)
            except Exception as e:
                send_msg(conn, {'status': 'nack', 'reason': 'decrypt_failed'})
                log_event(f"Decrypt failed from {addr}: {e}")
                return

            if compute_checksum(plaintext) != checksum:
                send_msg(conn, {'status': 'nack', 'reason': 'checksum_mismatch'})
                log_event(f"Checksum mismatch for msg id={msg.get('id')} from {addr}")
                return

            # multi-hop
            if msg.get('route'):
                if forward_to_next_hop(msg):
                    send_msg(conn, {'status': 'forwarded'})
                    return

            # store locally
            urgent = bool(msg.get('urgent'))
            with store_lock:
                if urgent:
                    message_store[dest]['urgent'].append(msg)
                else:
                    message_store[dest]['normal'].append(msg)
            send_msg(conn, {'status': 'stored'})
            log_event(f"Stored msg id={msg.get('id')} dest={dest} urgent={urgent}")

        elif mtype == 'fetch_messages':
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
                time.sleep(0.05)
            send_msg(conn, {'status': 'done'})
            log_event(f"Delivered {len(urgent_msgs)+len(normal_msgs)} to {dest}")

        else:
            send_msg(conn, {'status': 'error', 'reason': 'unknown_type'})

    except Exception as e:
        log_event(f"Error handling client {addr}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def peer_server(host='0.0.0.0', port=8000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(10)
    log_event(f"IBMS Peer started on {host}:{port}")
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()


if __name__ == '__main__':
    peer_server()

