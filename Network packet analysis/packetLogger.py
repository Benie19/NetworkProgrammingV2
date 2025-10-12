import socket
import datetime
import struct

def parse_ip_header(packet):
    iph = struct.unpack('!BBHHHBBH4s4s', packet[:20])
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])
    return src_ip, dst_ip

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
sniffer.bind(("0.0.0.0", 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
log_file = open("packet_log.txt", "a")
print("Logging packets...")

while True:
    packet = sniffer.recvfrom(65565)[0]
    timestamp = datetime.datetime.now()
    src_ip, dst_ip = parse_ip_header(packet)
    payload = packet[40:64]  # TCP header is usually 20 bytes after IP header
    log_entry = f"{timestamp} | {src_ip} -> {dst_ip} | Payload: {payload}\n"
    print(log_entry)
    log_file.write(log_entry)