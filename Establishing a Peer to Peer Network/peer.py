import socket
import threading
import time
from Crypto.Cipher import AES
import os

TRUSTED_SECRET = b"mars2025"
BOOTSTRAP_ADDR = ("127.0.0.1", 4000)
AES_KEY = b"ThisIsA32ByteLongSecretKey1234567890!!"  # 32 bytes

def pad(msg):
    pad_len = 16 - (len(msg) % 16)
    return msg + (chr(pad_len) * pad_len)

def unpad(msg):
    pad_len = msg[-1]
    return msg[:-pad_len]

def encrypt_message(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(message).encode())

def decrypt_message(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext)).decode()

def listen_for_messages(listen_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", listen_port))
    s.listen(5)
    print(f"Peer listening on port {listen_port}...")
    while True:
        conn, addr = s.accept()
        try:
            # Authenticate sender
            secret = conn.recv(32)
            if secret != TRUSTED_SECRET:
                conn.close()
                continue
            iv = conn.recv(16)
            msg_len = int.from_bytes(conn.recv(4), "big")
            ciphertext = conn.recv(msg_len)
            message = decrypt_message(ciphertext, AES_KEY, iv)
            print(f"Received from {addr}: {message}")
        except Exception as e:
            print(f"Error receiving message: {e}")
        finally:
            conn.close()

def send_encrypted_message(peer_ip, peer_port, message):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((peer_ip, peer_port))
    s.sendall(TRUSTED_SECRET)
    iv = os.urandom(16)
    ciphertext = encrypt_message(message, AES_KEY, iv)
    s.sendall(iv)
    s.sendall(len(ciphertext).to_bytes(4, "big"))
    s.sendall(ciphertext)
    s.close()

def discover_peers(my_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(BOOTSTRAP_ADDR)
    s.sendall(TRUSTED_SECRET)
    s.sendall(my_port.to_bytes(4, "big"))
    peer_list = eval(s.recv(4096).decode())
    s.close()
    return peer_list

if __name__ == "__main__":
    import sys
    my_port = int(sys.argv[1])  # Each peer runs on a different port
    threading.Thread(target=listen_for_messages, args=(my_port,), daemon=True).start()
    time.sleep(1)
    peers = discover_peers(my_port)
    print(f"Discovered peers: {peers}")

    # Send a message to all discovered peers
    for peer_ip, peer_port in peers:
        send_encrypted_message(peer_ip, peer_port, f"Hello from peer {my_port}!")

    # Keep running to receive messages
    while True:
        time.sleep(10)