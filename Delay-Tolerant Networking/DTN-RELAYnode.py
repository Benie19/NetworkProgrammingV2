import socket
import time
import pickle
import threading
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# encryption key (must match sender)
PASSWORD = b"dtn-secret"
SALT = b"dtn-salt"
KEY = PBKDF2(PASSWORD, SALT, dkLen=32, count=100_000)

# Simple in-memory store: destination -> { 'urgent': [msgs], 'normal': [msgs] }
message_store = {}
store_lock = threading.Lock()

HOST = "0.0.0.0"
PORT = 6000


def send_msg(conn, obj):
    """Send a pickled object with a 4-byte big-endian length prefix."""
    data = pickle.dumps(obj)
    length = len(data).to_bytes(4, 'big')
    conn.sendall(length + data)


def recv_msg(conn):
    """Receive a pickled object sent with send_msg framing."""
    len_b = conn.recv(4)
    if not len_b:
        return None
    total = int.from_bytes(len_b, 'big')
    chunks = bytearray()
    while len(chunks) < total:
        chunk = conn.recv(min(4096, total - len(chunks)))
        if not chunk:
            raise ConnectionError("socket closed while reading message")
        chunks.extend(chunk)
    return pickle.loads(bytes(chunks))


def compute_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def aes_decrypt(key: bytes, blob: bytes) -> bytes:
    iv = blob[:16]
    tag = blob[16:32]
    ciphertext = blob[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)


def forward_to_next_hop(message: dict):
    """If message contains a 'route' list of (host,port), attempt to forward to next hop."""
    route = message.get('route')
    if not route:
        return False
    # route is expected as list of (host, port) tuples
    next_hop = route.pop(0)
    try:
        with socket.create_connection(next_hop, timeout=5) as s:
            send_msg(s, message)
        print(f"Forwarded message to next hop {next_hop}")
        return True
    except Exception as e:
        print(f"Failed to forward to {next_hop}: {e}")
        # put the hop back so it can be retried later
        route.insert(0, next_hop)
        return False


def handle_client(conn, addr):
    try:
        msg = recv_msg(conn)
        if msg is None:
            return

        status = msg.get('status')
        if status == 'store':
            dest = msg.get('destination')
            urgent = bool(msg.get('urgent'))
            payload = msg.get('payload')  # bytes (encrypted)
            checksum = msg.get('checksum')

            # Decrypt to validate checksum (we still store the encrypted blob)
            try:
                plaintext = aes_decrypt(KEY, payload)
            except Exception as e:
                print(f"Decryption failed for message from {msg.get('from')} -> {dest}: {e}")
                send_msg(conn, {'status': 'nack', 'reason': 'decrypt_failed'})
                return

            calc = compute_checksum(plaintext)
            if checksum != calc:
                print(f"Checksum mismatch for message from {msg.get('from')} -> {dest}. Dropping.")
                send_msg(conn, {'status': 'nack', 'reason': 'checksum_mismatch'})
                return

            # Optional multi-hop forwarding
            route = msg.get('route')
            if route:
                forwarded = forward_to_next_hop(msg)
                if forwarded:
                    send_msg(conn, {'status': 'forwarded'})
                    return

            # Store message in priority queue
            with store_lock:
                bucket = message_store.setdefault(dest, {'urgent': [], 'normal': []})
                if urgent:
                    bucket['urgent'].append(msg)
                else:
                    bucket['normal'].append(msg)
            print(f"Stored message for {dest} (urgent={urgent}) from {msg.get('from')}")
            send_msg(conn, {'status': 'stored'})

        elif status == 'fetch':
            dest = msg.get('destination')
            # fetch messages for this destination (urgent first)
            with store_lock:
                bucket = message_store.get(dest, {'urgent': [], 'normal': []})
                urgent_msgs = bucket['urgent'][:]
                normal_msgs = bucket['normal'][:]
                # clear stored messages for this dest
                message_store[dest] = {'urgent': [], 'normal': []}

            # send urgent then normal
            for m in urgent_msgs + normal_msgs:
                send_msg(conn, m)
                time.sleep(0.1)
            send_msg(conn, {'status': 'done'})
            print(f"Delivered {len(urgent_msgs)+len(normal_msgs)} messages to {dest}")

        else:
            print(f"Unknown status from {addr}: {status}")
            send_msg(conn, {'status': 'error', 'reason': 'unknown_status'})

    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def relay_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)
    print("DTN Relay Node is running...")
    while True:
        conn, addr = server_socket.accept()
        print(f"Connected to {addr}")
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()


if __name__ == '__main__':
    relay_server()