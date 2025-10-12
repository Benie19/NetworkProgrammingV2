import socket
import struct
import time

# Define known devices and their shared keys
devices = {
    1: ("Rover-1", b"roverkey"),
    2: ("SolarPanel-1", b"solarkey"),
    3: ("LifeSupport-1", b"lifekey"),
    4: ("Habitat-1", b"habkey"),
    5: ("Sensor-1", b"senkey"),
    6: ("CommArray-1", b"commkey")
}

COMMANDS = {
    0x01: "TURN_ON",
    0x02: "TURN_OFF",
    0x03: "SET_PARAM",
    0x04: "GET_STATUS",
    0x05: "ADJUST_TEMP",
    0x06: "ACTIVATE_SENSOR"
}

def log_event(event):
    with open("c2_server_log.txt", "a") as log:
        log.write(f"{time.ctime()} | {event}\n")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(("0.0.0.0", 5000))
print("C2 Server is running...")

while True:
    data, addr = server_socket.recvfrom(1024)
    # Unpack: cmd_id (1), device_id (2), payload_len (1), key_len (1), key (var), payload (var)
    cmd_id, device_id, payload_len, key_len = struct.unpack("!B H B B", data[:5])
    key = data[5:5+key_len]
    payload = data[5+key_len:5+key_len+payload_len].decode(errors="replace")
    device_info = devices.get(device_id)
    if not device_info:
        log_event(f"ERROR: Unknown device {device_id} from {addr}")
        continue
    device_name, shared_key = device_info
    # Authenticate
    if key != shared_key:
        log_event(f"AUTH_FAIL: {device_name} from {addr}")
        response = "ERROR: Authentication failed"
        server_socket.sendto(response.encode(), addr)
        continue
    # Process command
    if cmd_id == 0x01:
        response = f"ACK: {device_name} turned ON"
    elif cmd_id == 0x02:
        response = f"ACK: {device_name} turned OFF"
    elif cmd_id == 0x03:
        response = f"ACK: {device_name} parameter set to {payload}"
    elif cmd_id == 0x04:
        response = f"STATUS: {device_name} is operational"
    elif cmd_id == 0x05:
        response = f"ACK: {device_name} temperature adjusted to {payload}"
    elif cmd_id == 0x06:
        response = f"ACK: {device_name} sensor activated"
    else:
        response = "ERROR: Unknown command"
    log_event(f"CMD {COMMANDS.get(cmd_id, 'UNKNOWN')} for {device_name} ({device_id}) from {addr} | Payload: {payload} | RESP: {response}")
    server_socket.sendto(response.encode(), addr)
