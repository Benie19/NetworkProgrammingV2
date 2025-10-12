import socket
import struct

# Create UDP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(("0.0.0.0", 12345))
print("LCP-2 Server is waiting for messages...")

expected_seq = {}  # Track expected sequence per client (by address)

def log_event(event):
    with open("lcp2_server_log.txt", "a") as log:
        log.write(event + "\n")

while True:
    data, addr = server_socket.recvfrom(4096) # Increased buffer size to 4096
    seq_num, ack_flag, msg_length = struct.unpack("!IBH", data[:7])
    payload = data[7:7+msg_length].decode(errors="replace")
    client_id = f"{addr[0]}:{addr[1]}"
    if client_id not in expected_seq:
        expected_seq[client_id] = 0

    # Check if packet is in order
    if seq_num == expected_seq[client_id]:
        print(f"Received from {client_id}: {payload} (Seq: {seq_num})")
        log_event(f"RECEIVED {client_id} Seq:{seq_num} Msg:{payload}")
        expected_seq[client_id] += 1
        # Send acknowledgment (ACK) back
        ack_packet = struct.pack("!IBH", seq_num, 1, 0) # ACK Flag = 1
        server_socket.sendto(ack_packet, addr)
    else:
        print(f"Out-of-order packet from {client_id} (Seq: {seq_num}), expected {expected_seq[client_id]}")
        log_event(f"RETRANSMISSION {client_id} Seq:{seq_num} Expected:{expected_seq[client_id]}")
        # Optionally, send ACK for last correct packet (not required for simple retransmission)