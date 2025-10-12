import socket
import struct
import time

dns_registry = {}
query_cache = {}  # name -> (ip_address, timestamp)
CACHE_TTL = 60    # seconds

def log_event(event):
    with open("marsdns_log.txt", "a") as log:
        log.write(f"{time.ctime()} | {event}\n")

def handle_request(data, addr, server_socket):
    msg_type, name_length = struct.unpack("!BB", data[:2])
    name = data[2:2 + name_length].decode()
    if msg_type == 0x01:  # Register
        ip_address = struct.unpack("!4s", data[2 + name_length:])[0]
        dns_registry[name] = ip_address
        log_event(f"REGISTER {name} -> {socket.inet_ntoa(ip_address)} from {addr}")
        print(f"Registered: {name} -> {socket.inet_ntoa(ip_address)}")
        response = struct.pack("!BB", 0x03, 0)  # Response success
    elif msg_type == 0x02:  # Query
        # Check cache first
        cache_entry = query_cache.get(name)
        now = time.time()
        if cache_entry and now - cache_entry[1] < CACHE_TTL:
            ip_address = cache_entry[0]
            log_event(f"CACHE_HIT {name} -> {socket.inet_ntoa(ip_address)} for {addr}")
            print(f"Cache hit: {name} -> {socket.inet_ntoa(ip_address)}")
            response = struct.pack("!BB4s", 0x03, name_length, ip_address)
        elif name in dns_registry:
            ip_address = dns_registry[name]
            query_cache[name] = (ip_address, now)
            log_event(f"QUERY {name} -> {socket.inet_ntoa(ip_address)} for {addr}")
            print(f"Resolved {name} -> {socket.inet_ntoa(ip_address)}")
            response = struct.pack("!BB4s", 0x03, name_length, ip_address)
        else:
            log_event(f"QUERY_FAIL {name} not found for {addr}")
            print(f"Name not found: {name}")
            response = struct.pack("!BB", 0x04, 0)  # Error: Name not found
    else:
        log_event(f"INVALID_MSG_TYPE {msg_type} from {addr}")
        response = struct.pack("!BB", 0x04, 0)  # Error: Invalid message
    server_socket.sendto(response, addr)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(("0.0.0.0", 5050))
print("MarsDNS Server is running...")

while True:
    data, addr = server_socket.recvfrom(1024)
    handle_request(data, addr, server_socket)