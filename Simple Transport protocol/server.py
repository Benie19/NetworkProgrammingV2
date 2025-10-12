import socket
import struct
import hashlib
import time

def compute_checksum(data):
    return hashlib.md5(data).digest()[:2]

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(("0.0.0.0", 12345))
print("LCP-3 Server is running...")

expected_seq = {}  # Track expected sequence per client (by conn_id)
connections = {}

def log_event(event):
    with open("lcp3_server_log.txt", "a") as log:
        log.write(event + "\n")

while True:
    data, addr = server_socket.recvfrom(4096)
    conn_id, seq_num, ack_flag, window_size, checksum, msg_length = struct.unpack("!H I B B 2s H", data[:12])
    payload = data[12:12+msg_length]
    client_key = (addr, conn_id)
    if client_key not in expected_seq:
        expected_seq[client_key] = 0

    # Simulate network delay (for retransmission testing)
    time.sleep(0.1)

    # Validate checksum
    if compute_checksum(payload) != checksum:
        print(f"Packet {seq_num} from {addr} has checksum error, requesting retransmission.")
        log_event(f"CHECKSUM_ERROR {addr} Conn:{conn_id} Seq:{seq_num}")
        nack_packet = struct.pack("!H I B B 2s H", conn_id, seq_num, 2, 0, b'\x00\x00', 0)
        server_socket.sendto(nack_packet, addr)
        continue

    # Ensure sequence order
    if seq_num == expected_seq[client_key]:
        try:
            msg = payload.decode()
        except Exception:
            msg = str(payload)
        print(f"Received Packet {seq_num} from {addr}: {msg}")
        log_event(f"RECEIVED {addr} Conn:{conn_id} Seq:{seq_num} Msg:{msg}")
        expected_seq[client_key] += 1
        # Send acknowledgment (ACK)
        ack_packet = struct.pack("!H I B B 2s H", conn_id, seq_num, 1, 0, b'\x00\x00', 0)
        server_socket.sendto(ack_packet, addr)
    else:
        print(f"Out-of-order packet from {addr} (Seq: {seq_num}), expected {expected_seq[client_key]}")
        log_event(f"RETRANSMISSION {addr} Conn:{conn_id} Seq:{seq_num} Expected:{expected_seq[client_key]}")
        # Optionally, send ACK for last correct packet (not required for simple retransmission)
