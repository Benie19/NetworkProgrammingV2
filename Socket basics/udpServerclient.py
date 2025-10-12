import socket
# Create a UDP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Send a message to the server
client_socket.sendto(b"Hello from Mars!", ("127.0.0.1", 12345))
# Receive a response
response, server_address = client_socket.recvfrom(1024)
print(f"Server says: {response.decode()}")
client_socket.close()