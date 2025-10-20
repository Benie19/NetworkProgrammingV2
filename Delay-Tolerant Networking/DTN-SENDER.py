import socket
import pickle
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

server_address = ("127.0.0.1", 6000)

# Encryption key derivation (must match relay's expectations in this example)
PASSWORD = b"dtn-secret"
SALT = b"dtn-salt"
KEY = PBKDF2(PASSWORD, SALT, dkLen=32, count=100_000)


def send_msg(conn, obj):
    data = pickle.dumps(obj)
    conn.sendall(len(data).to_bytes(4, 'big') + data)


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return iv + tag + ciphertext


def compute_checksum(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def send_message(destination, message_text, urgent=False, route=None):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(server_address)

    payload = message_text.encode('utf-8')
    checksum = compute_checksum(payload)
    # encrypt payload before sending to relay
    encrypted = aes_encrypt(KEY, payload)

    packet = {
        'status': 'store',
        'from': 'sender1',
        'destination': destination,
        'urgent': urgent,
        'payload': encrypted,
        'checksum': checksum,
    }
    if route:
        packet['route'] = route

    send_msg(client_socket, packet)
    # wait for ack
    # naive recv framed ack
    len_b = client_socket.recv(4)
    if len_b:
        total = int.from_bytes(len_b, 'big')
        ack = pickle.loads(client_socket.recv(total))
        print('Relay response:', ack)
    client_socket.close()


if __name__ == '__main__':
    send_message('rover1', 'Data from Mars rover - Solar Panel Efficiency Report', urgent=True)