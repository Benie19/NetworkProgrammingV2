import socket
import struct

def send_lcp1_message(sock, msg_type, message):
    try:
        if msg_type == 0x02:  # Sensor data (float)
            payload = struct.pack("!f", message)
        else:
            payload = str(message).encode()
        header = struct.pack("!BI", msg_type, len(payload))
        sock.sendall(header + payload)
    except Exception as e:
        print(f"Error sending message type {msg_type}: {e}")

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("127.0.0.1", 12345))

# Send Text Message
send_lcp1_message(client_socket, 0x01, "Hello, Mars!")
# Send Sensor Data
send_lcp1_message(client_socket, 0x02, 42.42)
# Send Alert
send_lcp1_message(client_socket, 0x03, "Warning: Low battery!")
# Send Unknown Type (for error handling test)
send_lcp1_message(client_socket, 0x99, "Unknown message type!")

client_socket.close()