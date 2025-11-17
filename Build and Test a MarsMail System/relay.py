import socket
import struct
import json
import time
import threading
import logging
from collections import defaultdict

# Per-recipient store
message_store = defaultdict(list)

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s', filename='marsmail.log')


def recv_framed_json(conn):
    # Read length prefix
    header = conn.recv(4)
    if not header or len(header) < 4:
        return None
    length = struct.unpack('>I', header)[0]
    data = b''
    while len(data) < length:
        chunk = conn.recv(min(4096, length - len(data)))
        if not chunk:
            break
        data += chunk
    if len(data) != length:
        return None
    return json.loads(data.decode('utf-8'))


def send_framed_json(conn, obj):
    payload = json.dumps(obj).encode('utf-8')
    conn.sendall(struct.pack('>I', len(payload)) + payload)


def handle_client(conn, addr):
    try:
        message = recv_framed_json(conn)
        if not message:
            return

        status = message.get('status')
        if status == 'store':
            recipient = message.get('recipient')
            message_store[recipient].append(message)
            logging.info(f"Stored message for {recipient} from {message.get('sender')}")
            print(f"📨 Message stored for {recipient}")
        elif status == 'fetch':
            recipient = message.get('recipient')
            msgs = message_store.get(recipient, [])
            for msg in msgs:
                try:
                    send_framed_json(conn, msg)
                    time.sleep(1)  # simulate delay
                except Exception:
                    logging.exception(f"Failed to forward message to {recipient}")
            # remove only forwarded messages
            if recipient in message_store:
                del message_store[recipient]
            logging.info(f"Forwarded {len(msgs)} messages to {recipient}")
            print(f"📤 Messages forwarded to {recipient}")
    except Exception:
        logging.exception(f"Error handling client {addr}")
    finally:
        conn.close()


def relay_server():
    """Stores and forwards MarsMail messages."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", 9300))
    server_socket.listen(5)

    print("📡 MarsMail Relay Node Active...")

    while True:
        conn, addr = server_socket.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()


if __name__ == '__main__':
    relay_server()

