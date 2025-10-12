import socket
import threading

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    try:
        while True:
            message = conn.recv(1024).decode()
            if not message:  # client disconnected
                break
            print(f"Received from {addr}: {message}")
            conn.sendall(f"Server received: {message}".encode())
    except Exception as e:
        print(f"[ERROR] Connection with {addr} failed: {e}")
    finally:
        conn.close()
        print(f"[DISCONNECTED] {addr} disconnected.")

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 12345))
    server_socket.listen(5)  # can handle multiple queued connections
    print("Server is waiting for connections...")

    try:
        while True:
            conn, addr = server_socket.accept()
            # Handle each client in a new thread
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()
