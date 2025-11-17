import socket
import struct
import json
import base64
import gzip
import rsa
import os
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

private_key = rsa.PrivateKey.load_pkcs1(open("receiver_private_key.pem", "rb").read())

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s', filename='marsmail.log')


def recv_framed_json(sock):
    header = sock.recv(4)
    if not header or len(header) < 4:
        return None
    length = struct.unpack('>I', header)[0]
    data = b''
    while len(data) < length:
        chunk = sock.recv(min(4096, length - len(data)))
        if not chunk:
            break
        data += chunk
    if len(data) != length:
        return None
    return json.loads(data.decode('utf-8'))


def send_framed_json(sock, obj):
    payload = json.dumps(obj).encode('utf-8')
    sock.sendall(struct.pack('>I', len(payload)) + payload)


def decrypt_and_process(message_packet, save_attachments_dir='attachments_received'):
    try:
        enc_key = base64.b64decode(message_packet['enc_key'])
        nonce = base64.b64decode(message_packet['nonce'])
        ciphertext = base64.b64decode(message_packet['ciphertext'])

        # Decrypt AES key with RSA private key
        aes_key = rsa.decrypt(enc_key, private_key)
        aesgcm = AESGCM(aes_key)
        compressed = aesgcm.decrypt(nonce, ciphertext, None)

        # Decompress and parse JSON
        plaintext = gzip.decompress(compressed)
        payload = json.loads(plaintext.decode('utf-8'))

        sender = payload.get('sender', message_packet.get('sender'))
        subject = payload.get('subject')
        body = payload.get('body')

        print(f"📥 Received Email from {sender}: Subject: {subject}\n{body}")
        logging.info(f"Successfully received message from {sender} (recipient {message_packet.get('recipient')})")

        # Save attachments
        attachments = payload.get('attachments', [])
        if attachments:
            os.makedirs(save_attachments_dir, exist_ok=True)
            for att in attachments:
                fname = att.get('filename', 'attachment')
                data = base64.b64decode(att.get('data', ''))
                path = os.path.join(save_attachments_dir, fname)
                with open(path, 'wb') as f:
                    f.write(data)
                logging.info(f"Saved attachment {path} from {sender}")

    except Exception:
        logging.exception("Failed to decrypt/process incoming message")


def fetch_messages(recipient):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 9300))

    fetch_request = {"recipient": recipient, "status": "fetch"}
    send_framed_json(client_socket, fetch_request)

    # Keep receiving framed JSON messages until connection closes
    while True:
        pkt = recv_framed_json(client_socket)
        if not pkt:
            break
        try:
            decrypt_and_process(pkt)
        except Exception:
            logging.exception(f"Error processing packet for recipient {recipient}")

    client_socket.close()


if __name__ == '__main__':
    # Example: Fetch messages for Earth Mission Control
    fetch_messages("earth_mission_control")