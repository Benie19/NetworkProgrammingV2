import socket
import pickle
import uuid
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

server_address = ("127.0.0.1", 8000)

# demo key (must match peer)
PASSWORD = b"ibms-demo-key"
SALT = b"ibms-salt"
KEY = PBKDF2(PASSWORD, SALT, dkLen=32, count=100_000)


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return iv + tag + ciphertext


def compute_checksum(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


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


def send_message(destination, text, urgent=False, route=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(server_address)

    msg_id = str(uuid.uuid4())
    plaintext = text.encode('utf-8')
    checksum = compute_checksum(plaintext)
    encrypted = aes_encrypt(KEY, plaintext)

    packet = {
        'id': msg_id,
        'type': 'store_message',
        'from': 'baseA',
        'destination': destination,
        'urgent': urgent,
        'payload': encrypted,
        'checksum': checksum
    }
    if route:
        packet['route'] = route

    send_msg(sock, packet)
    resp = recv_msg(sock)
    print('Peer response:', resp)
    sock.close()


if __name__ == '__main__':
    # Example: send a message to another base
    send_message('baseB', 'Telemetry: battery 87%', urgent=True)