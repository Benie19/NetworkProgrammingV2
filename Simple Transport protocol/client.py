import socket
import struct
import hashlib
import time
import random
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ("127.0.0.1", 12345)
conn_id = random.randint(1, 65535) # Unique connection ID
sequence_number = 0 # Initialize sequence number
window_size = 3 # Maximum packets allowed in transit
# Function to compute checksum
def compute_checksum(data):
    return hashlib.md5(data).digest()[:2]
def send_lcp3_message(message, drop=False, delay=0):
    global sequence_number
    payload = message.encode()
    checksum = compute_checksum(payload)
    header = struct.pack("!H I B B 2s H", conn_id, sequence_number, 0, 0, checksum, len(payload))
    packet = header + payload
    if drop:
        print(f"Intentionally dropping packet Seq:{sequence_number}")
        sequence_number += 1
        return
    if delay > 0:
        print(f"Simulating network delay of {delay}s for Seq:{sequence_number}")
        time.sleep(delay)
    client_socket.sendto(packet, server_address) # Send the packet
    # Wait for acknowledgment (ACK)
    client_socket.settimeout(2.0) # Timeout after 2 seconds
    try:
        ack_data, _ = client_socket.recvfrom(1024)
        ack_conn, ack_seq, ack_flag, _, _, _ = struct.unpack("!H I B B 2sH", ack_data[:12])
        if ack_flag == 1 and ack_seq == sequence_number:
            print(f"ACK received for Seq: {sequence_number}")
            sequence_number += 1 # Increment sequence number for next message
        else:
            print("Incorrect ACK received")
    except socket.timeout:
            print("No ACK received, resending packet...")
            send_lcp3_message(message) # Resend if no ACK received
# Sending messages
send_lcp3_message("Hello, Mars!")
# Simulate packet loss
send_lcp3_message("This packet will be dropped!", drop=True)
# Simulate network delay
send_lcp3_message("Delayed packet!", delay=0.5)
# Send a file (split into packets)
filename = "testfile.txt"
try:
    with open(filename, "rb") as f:
        while True:
            chunk = f.read(512)
            if not chunk:
                break
            send_lcp3_message(chunk)
except FileNotFoundError:
    print(f"File {filename} not found.")
client_socket.close()
