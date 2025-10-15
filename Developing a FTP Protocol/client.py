import socket
import struct
import hashlib
import os
from pathlib import Path

def compute_checksum(data):
    """Compute a simple checksum (first 2 bytes of MD5 hash)."""
    return hashlib.md5(data).digest()[:2]

server_address = ("127.0.0.1", 5500)

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(server_address)

file_path = "sample_file.txt"
chunk_size = 1024

with open(file_path, "rb") as file:
    file_data = file.read()

total_chunks = (len(file_data) + chunk_size - 1) // chunk_size  # Calculate total chunks

# New: local resume state file
state_path = Path(file_path + ".state")

# Handshake: ask server where to start
resume_msg = f"RESUME {file_path} {total_chunks - 1}\n".encode()
client_socket.sendall(resume_msg)

resp = client_socket.recv(1024).decode().strip()
start_chunk = 0
if resp.startswith("START"):
    try:
        start_chunk = int(resp.split()[1])
    except Exception:
        start_chunk = 0
elif resp.isdigit():
    start_chunk = int(resp)
else:
    # Unknown response; try local state if exists
    if state_path.exists():
        try:
            start_chunk = int(state_path.read_text().strip()) + 1
        except Exception:
            start_chunk = 0

# If local state indicates a later chunk, prefer the later one
if state_path.exists():
    try:
        local_last = int(state_path.read_text().strip())
        if local_last + 1 > start_chunk:
            start_chunk = local_last + 1
    except Exception:
        pass

print(f"Resuming from chunk {start_chunk} / {total_chunks - 1}")

for chunk_number in range(start_chunk, total_chunks):
    start = chunk_number * chunk_size
    end = start + chunk_size
    chunk = file_data[start:end]

    checksum = compute_checksum(chunk)
    header = struct.pack("!II2s", chunk_number, total_chunks, checksum)

    client_socket.sendall(header + chunk)
    
    # Wait for acknowledgment
    ack = client_socket.recv(1024)
    retries = 5
    while ack != b"ACK" and retries > 0:
        print(f"Retransmitting chunk {chunk_number}. Retries left: {retries}")
        client_socket.sendall(header + chunk)  # Retransmit if no ACK received
        ack = client_socket.recv(1024)
        retries -= 1
    if retries == 0:
        print(f"Failed to send chunk {chunk_number} after multiple attempts.")
        break

    # Update local state to remember the last successfully sent chunk
    try:
        state_path.write_text(str(chunk_number))
    except Exception:
        pass

    print(f"Chunk {chunk_number}/{total_chunks - 1} sent successfully.")

# On complete remove state file
if start_chunk <= total_chunks - 1 and (not state_path.exists() or int(state_path.read_text().strip()) == total_chunks - 1):
    try:
        state_path.unlink()
    except Exception:
        pass

print("File transfer complete.")
client_socket.close()