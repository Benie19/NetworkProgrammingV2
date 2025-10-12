import socket
import struct

MESSAGE_TYPES = {
    0x01: "Text",
    0x02: "Sensor",
    0x03: "Alert"
}

def receive_lcp1_message(conn):
    """Receives and decodes an LCP-1 formatted message."""
    # Read the message type (1 byte) and length (4 bytes)
    header = conn.recv(5)
    if not header:
        return None, None
    msg_type, msg_length = struct.unpack("!BI", header)
    # Read the payload
    payload = conn.recv(msg_length)
    return msg_type, payload

def log_message(msg_type, payload):
    """Logs the received message to a file."""
    with open("lcp1_server_log.txt", "a") as log:
        if msg_type in MESSAGE_TYPES:
            log.write(f"{MESSAGE_TYPES[msg_type]}: {payload}\n")
        else:
            log.write(f"ERROR: Unknown message type {msg_type}. Payload: {payload}\n")

# Set up the server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("0.0.0.0", 12345))
server_socket.listen(1)
print("LCP-1 Server is waiting for connections...")
conn, addr = server_socket.accept()
print(f"Connected to {addr}")

while True:
    msg_type, payload = receive_lcp1_message(conn)
    if msg_type is None:
        break
    if msg_type == 0x01:
        text = payload.decode()
        print(f"Received Text Message: {text}")
        log_message(msg_type, text)
    elif msg_type == 0x02:
        sensor_value = struct.unpack("!f", payload)[0]
        print(f"Received Sensor Data: {sensor_value}")
        log_message(msg_type, sensor_value)
    elif msg_type == 0x03:
        alert = payload.decode()
        print(f"Received Alert: {alert}")
        log_message(msg_type, alert)
    else:
        print(f"Unknown message type: {msg_type}")
        log_message(msg_type, payload)

conn.close()
server_socket.close()