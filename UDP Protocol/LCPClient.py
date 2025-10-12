import socket
import struct
import time

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ("127.0.0.1", 12345)
sequence_number = 0

def send_lcp2_message(message, drop=False):
    global sequence_number
    payload = message.encode()
    header = struct.pack("!IBH", sequence_number, 0, len(payload))
    packet = header + payload
    if drop:
        print(f"Intentionally dropping packet Seq:{sequence_number}")
        sequence_number += 1
        return  # Do not send
    client_socket.sendto(packet, server_address)
    client_socket.settimeout(2.0)
    try:
        ack_data, _ = client_socket.recvfrom(1024)
        ack_seq, ack_flag, _ = struct.unpack("!IBH", ack_data[:7])
        if ack_flag == 1 and ack_seq == sequence_number:
            print(f"ACK received for Seq: {sequence_number}")
            sequence_number += 1
        else:
            print("Incorrect ACK received")
    except socket.timeout:
        print("No ACK received, resending packet...")
        send_lcp2_message(message)  # Resend if no ACK

# Send normal messages
send_lcp2_message("Hello, Mars!")
send_lcp2_message("This is a reliable UDP protocol.")

# Intentionally drop a packet to test retransmission
send_lcp2_message("This packet will be dropped!", drop=True)
send_lcp2_message("LCP-2 ensures messages are received.")

# Send a large message split across multiple packets
large_message = "LCP-2 supports large messages. " * 20  # Make a big message
chunk_size = 50
for i in range(0, len(large_message), chunk_size):
    chunk = large_message[i:i+chunk_size]
    send_lcp2_message(f"[Chunk {i//chunk_size}] {chunk}")

client_socket.close()
