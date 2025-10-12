import socket
import threading
import pickle
import time

users = {}  # username -> (ip, port, online)
offline_messages = {}  # username -> [messages]
message_log = []  # [(timestamp, sender, recipients, message)]

def handle_client(conn, addr):
    try:
        data = conn.recv(4096)
        req = pickle.loads(data)
        if req['action'] == 'register':
            users[req['username']] = (addr[0], req['port'], True)
            offline_messages.setdefault(req['username'], [])
            conn.sendall(pickle.dumps({'status': 'ok', 'users': users}))
        elif req['action'] == 'get_users':
            conn.sendall(pickle.dumps({'users': users}))
        elif req['action'] == 'offline_messages':
            msgs = offline_messages.get(req['username'], [])
            conn.sendall(pickle.dumps({'messages': msgs}))
            offline_messages[req['username']] = []
        elif req['action'] == 'send_message':
            recipients = req['recipients']
            message = req['message']
            sender = req['sender']
            timestamp = time.ctime()
            message_log.append((timestamp, sender, recipients, message))
            for recipient in recipients:
                if recipient in users and users[recipient][2]:  # online
                    # Forward message (could use direct socket, but for demo just store)
                    offline_messages.setdefault(recipient, []).append((timestamp, sender, message))
                else:
                    offline_messages.setdefault(recipient, []).append((timestamp, sender, message))
            conn.sendall(pickle.dumps({'status': 'stored'}))
        elif req['action'] == 'get_log':
            conn.sendall(pickle.dumps({'log': message_log}))
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("0.0.0.0", 4100))
server_socket.listen(10)
print("Chat Server running...")

while True:
    conn, addr = server_socket.accept()
    threading.Thread(target=handle_client, args=(conn, addr)).start()