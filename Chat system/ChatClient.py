import socket
import threading
import pickle
from Crypto.Cipher import AES
import os

SERVER_ADDR = ("127.0.0.1", 4100)
AES_KEY = b"ThisIsA32ByteLongSecretKey1234567890!!"

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

def register(username, listen_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    req = {'action': 'register', 'username': username, 'port': listen_port}
    s.connect(SERVER_ADDR)
    s.sendall(pickle.dumps(req))
    resp = pickle.loads(s.recv(4096))
    s.close()
    return resp['users']

def get_offline_messages(username):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    req = {'action': 'offline_messages', 'username': username}
    s.connect(SERVER_ADDR)
    s.sendall(pickle.dumps(req))
    resp = pickle.loads(s.recv(4096))
    s.close()
    return resp['messages']

def send_message(sender, recipients, message):
    iv = os.urandom(16)
    ciphertext = encrypt_message(message, AES_KEY, iv)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    req = {
        'action': 'send_message',
        'sender': sender,
        'recipients': recipients,
        'message': (iv, ciphertext)
    }
    s.connect(SERVER_ADDR)
    s.sendall(pickle.dumps(req))
    resp = pickle.loads(s.recv(4096))
    s.close()
    return resp['status']

def get_message_log():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    req = {'action': 'get_log'}
    s.connect(SERVER_ADDR)
    s.sendall(pickle.dumps(req))
    resp = pickle.loads(s.recv(4096))
    s.close()
    return resp['log']

if __name__ == "__main__":
    username = input("Enter your username: ")
    listen_port = int(input("Enter your listening port: "))
    users = register(username, listen_port)
    print("Online users:", users)

    # Display offline messages
    offline_msgs = get_offline_messages(username)
    if offline_msgs:
        print("\n--- Offline Messages ---")
        for ts, sender, msg in offline_msgs:
            iv, ciphertext = msg
            message = decrypt_message(ciphertext, AES_KEY, iv)
            print(f"[{ts}] {sender}: {message}")
        print("-----------------------")

    # Chat loop
    while True:
        cmd = input("\nSend message (recipient1,recipient2,...) or 'log' to view history: ")
        if cmd.lower() == "exit":
            break
        if cmd.lower() == "log":
            log = get_message_log()
            print("\n--- Message Log ---")
            for ts, sender, recipients, msg in log:
                iv, ciphertext = msg
                message = decrypt_message(ciphertext, AES_KEY, iv)
                print(f"[{ts}] {sender} -> {recipients}: {message}")
            print("-------------------")
            continue
        recipients = [r.strip() for r in cmd.split(",")]
        message = input("Message: ")
        send_message(username, recipients, message)