import socket
import threading

TRUSTED_SECRET = b"mars2025"  # Shared secret for trusted peers
peers = set()  # Set of (ip, port) tuples

def handle_peer(conn, addr):
    global peers
    try:
        # Authenticate peer
        secret = conn.recv(32)
        if secret != TRUSTED_SECRET:
            conn.sendall(b"AUTH_FAIL")
            conn.close()
            return

        # Receive peer's listening port
        port_bytes = conn.recv(4)
        peer_port = int.from_bytes(port_bytes, "big")
        peer_info = (addr[0], peer_port)
        if peer_info not in peers:
            peers.add(peer_info)
            print(f"New peer added: {peer_info}")

        # Send updated peer list (excluding the connecting peer)
        peer_list = [p for p in peers if p != peer_info]
        conn.sendall(str(peer_list).encode())
    except Exception as e:
        print(f"Error handling peer: {e}")
    finally:
        conn.close()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("0.0.0.0", 4000))
server_socket.listen(5)
print("Bootstrap Node Running...")

while True:
    conn, addr = server_socket.accept()
    threading.Thread(target=handle_peer, args=(conn, addr)).start()

