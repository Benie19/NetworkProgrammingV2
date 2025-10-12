import socket
import struct
import sys

# Device simulation: choose device_id and key
DEVICES = {
    "rover": (1, b"roverkey"),
    "solar": (2, b"solarkey"),
    "life": (3, b"lifekey"),
    "hab": (4, b"habkey"),
    "sensor": (5, b"senkey"),
    "comm": (6, b"commkey")
}

COMMANDS = {
    "on": 0x01,
    "off": 0x02,
    "set": 0x03,
    "status": 0x04,
    "temp": 0x05,
    "activate": 0x06
}

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ("127.0.0.1", 5000)
def send_command(command_id, device_id, payload=""):
    payload_bytes = payload.encode()
    packet = struct.pack("!B H B", command_id, device_id,
len(payload_bytes)) + payload_bytes
    client_socket.sendto(packet, server_address)
    # Wait for response
    response, _ = client_socket.recvfrom(1024)
    print(f"Server Response: {response.decode()}")
# Example commands
send_command(0x01, 1) # TURN_ON Rover-1
send_command(0x03, 2, "75%") # SET_PARAM SolarPanel-1 to 75%
send_command(0x04, 3) # GET_STATUS LifeSupport-1
client_socket.close()