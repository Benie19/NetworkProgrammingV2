import socket
import struct
from Crypto.Cipher import AES
import os
import hmac
import hashlib
import time

SECRET_KEY = b"ThisIsA32ByteLongSecretKey1234567890!!"  # 32 bytes for AES-256

def pad(msg):
    pad_len = 16 - (len(msg) % 16)
    return msg + (chr(pad_len) * pad_len)

def generate_hmac(message, nonce, key):
    return hmac.new(key, (nonce + message).encode(), hashlib.sha256).hexdigest()

def encrypt_message(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(message).encode()
    return cipher.encrypt(padded_message)

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ("127.0.0.1", 6000)

# Generate a unique nonce (timestamp + random)
nonce = str(int(time.time())) + os.urandom(4).hex()
message = "TURN_ON_SOLAR_PANEL 75%"
hmac_value = generate_hmac(message, nonce, SECRET_KEY)
iv = os.urandom(16)
encrypted = encrypt_message(message, SECRET_KEY, iv)

# Send: [nonce_len][nonce][iv][hmac][encrypted]
nonce_bytes = nonce.encode()
hmac_bytes = hmac_value.encode()
packet = struct.pack("!B", len(nonce_bytes)) + nonce_bytes + iv + struct.pack("!H", len(hmac_bytes)) + hmac_bytes + encrypted

client_socket.sendto(packet, server_address)
print("Secure message sent.")
client_socket.close()
