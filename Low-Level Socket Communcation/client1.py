import socket
import struct

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("127.0.0.1", 12345))

# Choose message type: 1=Text, 2=Sensor Data, 3=Alert
msg_type = 1

if msg_type == 1:
    message = "Hello from Mars!"
    payload = message.encode()
elif msg_type == 2:
    sensor_value = 42.42
    payload = struct.pack("f", sensor_value)
elif msg_type == 3:
    alert = "Warning: Low battery!"
    payload = alert.encode()
else:
    payload = b""

header = struct.pack("<BI", msg_type, len(payload))
client_socket.sendall(header + payload)
client_socket.close()