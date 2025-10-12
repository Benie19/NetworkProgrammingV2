import socket

def main():
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(("127.0.0.1", 12345))
        print("Connected to server.")

        while True:
            msg = input("Enter message (or 'quit' to exit): ")
            if msg.lower() == "quit":
                break

            client_socket.sendall(msg.encode())
            response = client_socket.recv(1024).decode()
            print(f"Server says: {response}")

    except ConnectionRefusedError:
        print("Could not connect to the server. Make sure it is running.")
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        client_socket.close()
        print("Connection closed.")

if __name__ == "__main__":
    main()
