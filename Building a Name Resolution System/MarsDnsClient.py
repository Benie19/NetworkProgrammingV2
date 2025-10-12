import socket
import struct

server_address = ("127.0.0.1", 5050)

def register_name(name, ip_address):
    name_bytes = name.encode()
    ip_bytes = socket.inet_aton(ip_address) # Convert IP string to bytes
    packet = struct.pack("!BB", 0x01, len(name_bytes)) + name_bytes + struct.pack("!4s", ip_bytes)
    client_socket.sendto(packet, server_address)
    print(f"Registered: {name} -> {ip_address}")

def query_name(name):
    name_bytes = name.encode()
    packet = struct.pack("!BB", 0x02, len(name_bytes)) + name_bytes
    client_socket.sendto(packet, server_address)
    data, _ = client_socket.recvfrom(1024)
    msg_type = data[0]
    if msg_type == 0x03:
        _, name_length, ip_address = struct.unpack("!BB4s", data)
        print(f"Resolved: {name} -> {socket.inet_ntoa(ip_address)}")
    else:
        print(f"Query failed: {name} not found.")

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Register multiple device names
devices = {
    "rover1": "192.168.1.12",
    "sensor1": "192.168.1.20",
    "habitat1": "192.168.1.30"
}
for name, ip in devices.items():
    register_name(name, ip)

# Query multiple names (including one not registered)
names_to_query = ["rover1", "sensor1", "habitat1", "unknown_device"]
for name in names_to_query:
    query_name(name)

client_socket.close()