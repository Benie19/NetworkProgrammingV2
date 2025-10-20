import socket
import pickle
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

server_address = ("127.0.0.1", 6000)

# Encryption key derivation (must match sender's/relay's expectations)
PASSWORD = b"dtn-secret"
SALT = b"dtn-salt"
KEY = PBKDF2(PASSWORD, SALT, dkLen=32, count=100_000)


def recv_msg(sock):
    len_b = sock.recv(4)
    if not len_b:
        return None
    total = int.from_bytes(len_b, 'big')
    chunks = bytearray()
    while len(chunks) < total:
        chunk = sock.recv(min(4096, total - len(chunks)))
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


def compute_checksum(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def fetch_messages():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(server_address)
    fetch_request = {"status": "fetch", "destination": "rover1"}
    # send framed request
    data = pickle.dumps(fetch_request)
    client_socket.sendall(len(data).to_bytes(4, 'big') + data)

    while True:
        msg = recv_msg(client_socket)
        if msg is None:
            break
        if msg.get('status') == 'done':
            print('No more messages')
            break
        # decrypt payload
        encrypted = msg.get('payload')
        try:
            plaintext = aes_decrypt(KEY, encrypted)
        except Exception as e:
            print('Decryption failed:', e)
            continue
        checksum = msg.get('checksum')
        if compute_checksum(plaintext) != checksum:
            print('Checksum mismatch; message corrupted')
            continue
        print(f"Received DTN Message for {msg.get('destination')}: {plaintext.decode('utf-8')}")

    client_socket.close()


if __name__ == '__main__':
    fetch_messages()