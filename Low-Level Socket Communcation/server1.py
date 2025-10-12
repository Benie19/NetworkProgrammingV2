import socket
import struct

MESSAGE_TYPES = {
    1: "Text Message",
    2: "Sensor Data",
    3: "Alert"
}

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("0.0.0.0", 12345))
server_socket.listen(1)
print("Server waiting for connection...")
conn, addr = server_socket.accept()
print(f"Connected to {addr}")

# Receive the message type (1 byte) and length (4 bytes)
header = conn.recv(5)
if len(header) < 5:
    print("Incomplete header received.")
    conn.close()
    server_socket.close()
    exit()

msg_type, msg_length = struct.unpack("<BI", header)
print(f"Message Type: {MESSAGE_TYPES.get(msg_type, 'Unknown')} ({msg_type})")
print(f"Message Length: {msg_length}")

# Receive the actual message payload
payload = conn.recv(msg_length)
if msg_type == 1:  # Text Message
    print(f"Received Text: {payload.decode()}")
elif msg_type == 2:  # Sensor Data (assume float)
    sensor_value = struct.unpack("f", payload)[0]
    print(f"Received Sensor Data: {sensor_value}")
elif msg_type == 3:  # Alert (assume text)
    print(f"Received Alert: {payload.decode()}")
else:
    print(f"Unknown message type. Raw payload: {payload}")

conn.close()
server_socket.close()