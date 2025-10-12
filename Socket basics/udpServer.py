import socket
# Create a UDP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Bind the socket to a local address and port
server_socket.bind(("0.0.0.0", 12345))
print("UDP Server is waiting for messages...")
# Receive data
data, addr = server_socket.recvfrom(1024)
print(f"Received message from {addr}: {data.decode()}")
# Send a response
server_socket.sendto(b"Message received!", addr)