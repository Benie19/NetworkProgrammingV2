import socket
import struct
import threading
import time

base_port = 6000
registered_peers = {}  # Dictionary to store registered peers {username: (ip, port)}
known_bootstrap_servers = set()  # Set of known bootstrap server ports
pending_messages = {}  # Dictionary to store messages for offline users {username: [messages]}

def listen_for_messages(peer_id):
    """Listens for incoming chat messages from peers."""
    listen_port = 7001 + peer_id  # Use unique port for each peer
    peer_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer_socket.bind(("0.0.0.0", listen_port))  # Open a listening port
    print(f"Listening for messages on port {listen_port}")

    while True:
        data, addr = peer_socket.recvfrom(1024)
        msg_type, username_length = struct.unpack("!BB", data[:2])
        username = data[2:2+username_length].decode()
        message_length = data[2+username_length]
        message = data[3+username_length:3+username_length+message_length].decode()
        print(f"[{username}] {message}")

def sync_with_other_bootstraps(peer_id):
    """Synchronize registered peers with other bootstrap servers."""
    global pending_messages
    while True:
        for port in range(base_port, base_port + 10):  # Check ports 6000-6009
            if port != base_port + peer_id:  # Don't sync with self
                try:
                    sync_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sync_socket.settimeout(1)
                    # Request peer list from other bootstrap server
                    sync_socket.sendto(struct.pack("!B", 0x03), ("127.0.0.1", port))
                    data, addr = sync_socket.recvfrom(1024)
                    
                    msg_type, peer_count = struct.unpack("!BB", data[:2])
                    if msg_type == 0x03:
                        offset = 2
                        for _ in range(peer_count):
                            username_length = struct.unpack("!B", data[offset:offset+1])[0]
                            offset += 1
                            username = data[offset:offset+username_length].decode()
                            offset += username_length
                            ip = socket.inet_ntoa(data[offset:offset+4])
                            offset += 4
                            port_peer = struct.unpack("!H", data[offset:offset+2])[0]
                            offset += 2
                            
                            # Add to our registry if not already present
                            if username not in registered_peers:
                                registered_peers[username] = (ip, port_peer)
                                
                    sync_socket.close()
                except:
                    pass
                    
        print(f"Synchronized peers: {registered_peers}")
        print(f"Pending messages: {list(pending_messages.keys())}")
        time.sleep(5)  # Sync every 5 seconds

def bootstrap_server(peer_id):
    """Bootstrap server that handles peer registration and provides peer lists."""
    global pending_messages
    server_port = base_port + peer_id
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("127.0.0.1", server_port))
    print(f"Bootstrap server started on 127.0.0.1:{server_port}")
    
    # Start sync thread
    threading.Thread(target=sync_with_other_bootstraps, args=(peer_id,), daemon=True).start()
    
    while True:
        data, addr = server_socket.recvfrom(1024)
        msg_type = struct.unpack("!B", data[:1])[0]
        
        if msg_type == 0x01:  # Peer registration
            username_length = struct.unpack("!B", data[1:2])[0]
            username = data[2:2+username_length].decode()
            port = struct.unpack("!H", data[2+username_length:4+username_length])[0]
            registered_peers[username] = (addr[0], port)
            print(f"Registered peer: {username} at {addr[0]}:{port}")
            
            # Send any local pending messages
            if username in pending_messages:
                print(f"Found {len(pending_messages[username])} local pending messages for {username}")
                for message_data in pending_messages[username]:
                    try:
                        msg_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        msg_socket.sendto(message_data, (addr[0], port))
                        msg_socket.close()
                    except Exception as e:
                        print(f"Failed to send pending message: {e}")
                del pending_messages[username]
            
            # Send acknowledgment
            server_socket.sendto(b"\x01", addr)
            
        elif msg_type == 0x05:  # Request for pending messages for specific user
            username_length = struct.unpack("!B", data[1:2])[0]
            username = data[2:2+username_length].decode()
            
            # Send back pending messages for this user
            if username in pending_messages:
                messages = pending_messages[username]
                # Send count first
                response = struct.pack("!BB", 0x06, len(messages))
                for msg in messages:
                    response += struct.pack("!H", len(msg)) + msg
                server_socket.sendto(response, addr)
                del pending_messages[username]  # Clear after sending
            else:
                # Send empty response
                server_socket.sendto(struct.pack("!BB", 0x06, 0), addr)
        
        elif msg_type == 0x04:  # Pending message sync from other bootstrap server
            username_length = struct.unpack("!B", data[1:2])[0]
            username = data[2:2+username_length].decode()
            message_data = data[2+username_length:]
            
            # Add to our pending messages if user not registered here
            if username not in registered_peers:
                if username not in pending_messages:
                    pending_messages[username] = []
                pending_messages[username].append(message_data)
                print(f"Received pending message for {username} from another bootstrap server")
            
        elif msg_type == 0x02:  # Message broadcast
            username_length = struct.unpack("!B", data[1:2])[0]
            username = data[2:2+username_length].decode()
            message_length = data[2+username_length]
            message = data[3+username_length:3+username_length+message_length].decode()
            
            # Broadcast message to all registered peers except sender
            for peer_name, (peer_ip, peer_port) in registered_peers.items():
                if peer_name != username:
                    try:
                        server_socket.sendto(data, (peer_ip, peer_port))
                    except:
                        pass
            
        elif msg_type == 0x03:  # Request for peer list
            # Send list of all registered peers
            peer_data = b""
            for username, (ip, port) in registered_peers.items():
                username_bytes = username.encode()
                ip_bytes = socket.inet_aton(ip)
                peer_data += struct.pack("!B", len(username_bytes)) + username_bytes + ip_bytes + struct.pack("!H", port)
            
            response = struct.pack("!BB", 0x03, len(registered_peers)) + peer_data
            server_socket.sendto(response, addr)

def send_message(username, receiver, message):
    """Sends a chat message to a specific peer by looking up their address."""
    username_bytes = username.encode()
    message_bytes = message.encode()
    packet = struct.pack("!BB", 0x02, len(username_bytes)) + username_bytes + struct.pack("!B", len(message_bytes)) + message_bytes
    
    # Check if receiver is registered in any bootstrap server
    receiver_found = False
    if receiver in registered_peers:
        receiver_ip, receiver_port = registered_peers[receiver]
        client_socket.sendto(packet, (receiver_ip, receiver_port))
        print(f"Message sent to {receiver} at {receiver_ip}:{receiver_port}")
        receiver_found = True
    else:
        # Check other bootstrap servers for the receiver
        for port in range(base_port, base_port + 10):
            try:
                check_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                check_socket.settimeout(0.5)
                check_socket.sendto(struct.pack("!B", 0x03), ("127.0.0.1", port))
                data, addr = check_socket.recvfrom(1024)
                
                msg_type, peer_count = struct.unpack("!BB", data[:2])
                if msg_type == 0x03:
                    offset = 2
                    for _ in range(peer_count):
                        peer_username_length = struct.unpack("!B", data[offset:offset+1])[0]
                        offset += 1
                        peer_username = data[offset:offset+peer_username_length].decode()
                        offset += peer_username_length
                        ip = socket.inet_ntoa(data[offset:offset+4])
                        offset += 4
                        peer_port = struct.unpack("!H", data[offset:offset+2])[0]
                        offset += 2
                        
                        if peer_username == receiver:
                            client_socket.sendto(packet, (ip, peer_port))
                            print(f"Message sent to {receiver} at {ip}:{peer_port}")
                            receiver_found = True
                            break
                            
                check_socket.close()
                if receiver_found:
                    break
            except:
                pass
    
    if not receiver_found:
        # Store message for offline user
        if receiver not in pending_messages:
            pending_messages[receiver] = []
        pending_messages[receiver].append(packet)
        print(f"User {receiver} is offline. Message stored for delivery.")
        print(f"Pending messages for {receiver}: {len(pending_messages[receiver])}")

def register_with_bootstrap(username, listen_port, peer_id):
    """Register this peer with the bootstrap server and collect pending messages."""
    server_port = base_port + peer_id
    username_bytes = username.encode()
    packet = struct.pack("!BB", 0x01, len(username_bytes)) + username_bytes + struct.pack("!H", listen_port)
    client_socket.sendto(packet, ("127.0.0.1", server_port))
    client_socket.recvfrom(1024)  # Wait for acknowledgment
    print(f"Registered with bootstrap server as {username}")
    
    # Now request pending messages from ALL bootstrap servers
    total_pending = 0
    for port in range(base_port, base_port + 10):
        try:
            request_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            request_socket.settimeout(2)
            request_packet = struct.pack("!BB", 0x05, len(username)) + username.encode()
            request_socket.sendto(request_packet, ("127.0.0.1", port))
            
            # Wait for response
            data, addr = request_socket.recvfrom(4096)
            msg_type, message_count = struct.unpack("!BB", data[:2])
            
            if msg_type == 0x06 and message_count > 0:
                print(f"Received {message_count} pending messages from bootstrap server {port}")
                offset = 2
                for i in range(message_count):
                    msg_length = struct.unpack("!H", data[offset:offset+2])[0]
                    offset += 2
                    message_data = data[offset:offset+msg_length]
                    offset += msg_length
                    
                    # Send the message to our listening port
                    delivery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    delivery_socket.sendto(message_data, ("127.0.0.1", listen_port))
                    delivery_socket.close()
                    total_pending += 1
                    
            request_socket.close()
        except Exception as e:
            pass  # Timeout or no server on this port
    
    if total_pending > 0:
        print(f"Delivered {total_pending} pending messages")

# Client setup
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

peer_id = int(input("Enter peer ID (0-9): "))
username = input("Enter your username: ")

# Start message listener thread with unique port
listen_port = 7001 + peer_id
threading.Thread(target=listen_for_messages, args=(peer_id,), daemon=True).start()

# Start bootstrap server thread with peer-specific port
threading.Thread(target=bootstrap_server, args=(peer_id,), daemon=True).start()

register_with_bootstrap(username, listen_port, peer_id)  # Register with bootstrap server
print(f"Welcome, {username}! Start chatting.")

while True:
    receiver = input("Enter username to send message to: ")
    message = input("Enter your message: ")
    send_message(username, receiver, message)