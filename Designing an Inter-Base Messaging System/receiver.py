import socket
import pickle
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import hashlib

server_address = ("127.0.0.1", 8000)

# demo key (must match peer)
PASSWORD = b"ibms-demo-key"
SALT = b"ibms-salt"
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


def fetch_messages(destination='baseB'):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(server_address)
    request = {'type': 'fetch_messages', 'destination': destination}
    data = pickle.dumps(request)
    client_socket.sendall(len(data).to_bytes(4, 'big') + data)

    while True:
        msg = recv_msg(client_socket)
        if msg is None:
            break
        if msg.get('status') == 'done':
            print('No more messages')
            break
        # decrypt and check
        encrypted = msg.get('payload')
        try:
            plaintext = aes_decrypt(KEY, encrypted)
        except Exception as e:
            print('Decryption failed:', e)
            continue
        if compute_checksum(plaintext) != msg.get('checksum'):
            print('Checksum mismatch; skipping')
            continue
        print(f"Received message id={msg.get('id')} from={msg.get('from')}: {plaintext.decode('utf-8')}")

    client_socket.close()


if __name__ == '__main__':
    fetch_messages()