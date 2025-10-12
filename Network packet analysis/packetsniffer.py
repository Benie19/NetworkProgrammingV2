import socket
# Create a raw socket to capture packets
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW,
socket.IPPROTO_TCP)
# Bind to localhost (adjust as needed)
sniffer.bind(("0.0.0.0", 0))
# Include IP headers in capture
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
print("Sniffing packets...")
while True:

    packet = sniffer.recvfrom(65565)[0]
    print(f"Captured Packet: {packet[:64]}")