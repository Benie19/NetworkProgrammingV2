import socket
import struct
from Crypto.Cipher import AES
import hmac
import hashlib

SECRET_KEY = b"ThisIsA32ByteLongSecretKey1234567890!!"  # 32 bytes for AES-256
used_nonces = set()

def unpad(msg):
    pad_len = msg[-1]
    return msg[:-pad_len]

def generate_hmac(message, nonce, key):
    return hmac.new(key, (nonce + message).encode(), hashlib.sha256).hexdigest()

def decrypt_message(encrypted, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted)
    return unpad(decrypted).decode(errors="replace")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(("0.0.0.0", 6000))
print("Secure C2 Server is running...")

while True:
    data, addr = server_socket.recvfrom(4096)
    offset = 0
    nonce_len = struct.unpack("!B", data[offset:offset+1])[0]
    offset += 1
    nonce = data[offset:offset+nonce_len].decode()
    offset += nonce_len
    iv = data[offset:offset+16]
    offset += 16
    hmac_len = struct.unpack("!H", data[offset:offset+2])[0]
    offset += 2
    hmac_value = data[offset:offset+hmac_len].decode()
    offset += hmac_len
    encrypted = data[offset:]

    # Log encrypted message
    with open("secure_c2_server_log.txt", "a") as log:
        log.write(f"From {addr} | Nonce: {nonce} | IV: {iv.hex()} | HMAC: {hmac_value} | Encrypted: {encrypted.hex()}\n")

    # Check for replay attack
    if nonce in used_nonces:
        print("Replay attack detected! Nonce reused.")
        continue
    used_nonces.add(nonce)

    # Decrypt and verify HMAC
    try:
        message = decrypt_message(encrypted, SECRET_KEY, iv)
        expected_hmac = generate_hmac(message, nonce, SECRET_KEY)
        if not hmac.compare_digest(hmac_value, expected_hmac):
            print("Invalid HMAC! Message rejected.")
            continue
        print(f"Received command: {message}")
        with open("secure_c2_server_log.txt", "a") as log:
            log.write(f"DECRYPTED: {message}\n")
    except Exception as e:
        print(f"Decryption or HMAC error: {e}")
