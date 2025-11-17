import socket
import struct
import json
import base64
import gzip
import rsa
import time
import os
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Generate RSA keys for encryption
public_key = rsa.PublicKey.load_pkcs1(open("receiver_public_key.pem", "rb").read())

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s', filename='marsmail.log')

def send_framed_json(sock, obj):
    payload = json.dumps(obj).encode('utf-8')
    sock.sendall(struct.pack('>I', len(payload)) + payload)

def encrypt_message_hybrid(message_bytes, recipient_public_key):
    """Compresses and encrypts message_bytes using AES-GCM, encrypts AES key with RSA.

    Returns a dict with base64-encoded fields: enc_key, nonce, ciphertext
    """
    # compress before encryption
    compressed = gzip.compress(message_bytes)

    # AES-GCM symmetric key
    aes_key = os.urandom(32)  # AES-256
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, compressed, None)

    # Encrypt AES key with receiver RSA public key
    enc_key = rsa.encrypt(aes_key, recipient_public_key)

    return {
        'enc_key': base64.b64encode(enc_key).decode('ascii'),
        'nonce': base64.b64encode(nonce).decode('ascii'),
        'ciphertext': base64.b64encode(ciphertext).decode('ascii')
    }

def send_email(sender, recipient, subject, body, attachments=None):
    """Sends an email-like message to a relay node.

    attachments: list of file paths to include
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 9300))  # Relay node

    timestamp = int(time.time())  # Current time

    # Build payload dict
    payload = {
        'subject': subject,
        'body': body,
        'timestamp': timestamp,
        'sender': sender,
        'attachments': []
    }

    if attachments:
        for path in attachments:
            try:
                with open(path, 'rb') as f:
                    data = f.read()
                payload['attachments'].append({
                    'filename': os.path.basename(path),
                    'data': base64.b64encode(data).decode('ascii')
                })
            except Exception as e:
                logging.exception(f"Failed to read attachment {path}: {e}")

    # Serialize, compress and encrypt (hybrid)
    message_bytes = json.dumps(payload).encode('utf-8')
    enc = encrypt_message_hybrid(message_bytes, public_key)

    email_packet = {
        'sender': sender,
        'recipient': recipient,
        'timestamp': timestamp,
        'enc_key': enc['enc_key'],
        'nonce': enc['nonce'],
        'ciphertext': enc['ciphertext'],
        'status': 'store'
    }

    try:
        send_framed_json(client_socket, email_packet)
        logging.info(f"Stored message for {recipient} from {sender}")
        print(f"📩 Message sent to relay for {recipient}")
    except Exception:
        logging.exception(f"Failed to send message for {recipient}")
    finally:
        client_socket.close()

if __name__ == '__main__':
    # Example: Send a message with an optional attachment
    send_email("mars_base_1", "earth_mission_control", "Mission Update", "Solar panels are fully operational.", attachments=None)