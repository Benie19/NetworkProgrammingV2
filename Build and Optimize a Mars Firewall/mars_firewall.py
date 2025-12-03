import logging
import sqlite3
from collections import defaultdict, deque
import geoip2.database
import time
import json

## --- Configuration ---
CONFIG_PATH = "firewall_config.json"
def load_config():
    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)
    return config

config = load_config()
ALLOWED_IPS = set(config["allowed_ips"])
BLOCKED_PORTS = set(config["blocked_ports"])
FAILED_ATTEMPTS = defaultdict(int)
ALLOWED_COUNTRIES = set(config["allowed_countries"])
RATE_LIMIT = config["rate_limit"]
RATE_WINDOW = config["rate_window"]
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"  # Download from MaxMind and place in same folder

try:
    geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
except FileNotFoundError:
    geoip_reader = None
    print("GeoIP database not found. Geo-restriction will be skipped.")

ip_request_log = defaultdict(lambda: deque())

# --- Logging Setup ---
logging.basicConfig(filename="mars_firewall.log", level=logging.INFO,
                    format="%(asctime)s - %(message)s")

# --- SQLite Setup ---
conn = sqlite3.connect("mars_firewall_secure.db")
c = conn.cursor()
c.execute("""
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    action TEXT,
    source_ip TEXT,
    destination_port INTEGER
)
""")
conn.commit()

def log_traffic(action, source_ip, destination_port):
    """Logs all network activity to file and database."""
    log_message = f"{action} - {source_ip} -> Port {destination_port}"
    logging.info(log_message)
    print(log_message)
    c.execute("INSERT INTO logs (timestamp, action, source_ip, destination_port) VALUES (datetime('now'), ?, ?, ?)",
              (action, source_ip, destination_port))
    conn.commit()

def detect_intrusion(source_ip):
    """Detect and block repeated unauthorized access attempts."""
    FAILED_ATTEMPTS[source_ip] += 1
    if FAILED_ATTEMPTS[source_ip] > 3:
        print(f"🚨 ALERT: Potential Intrusion Detected from {source_ip}! IP Blocked.")
        return False
    print(f"⚠ WARNING: Unauthorized attempt from {source_ip}. Attempt {FAILED_ATTEMPTS[source_ip]}")
    return True

def get_country_from_ip(ip):
    if geoip_reader is None:
        return None
    try:
        response = geoip_reader.country(ip)
        return response.country.iso_code
    except Exception:
        return None

def reload_rules():
    global config, ALLOWED_IPS, BLOCKED_PORTS, ALLOWED_COUNTRIES, RATE_LIMIT, RATE_WINDOW
    config = load_config()
    ALLOWED_IPS = set(config["allowed_ips"])
    BLOCKED_PORTS = set(config["blocked_ports"])
    ALLOWED_COUNTRIES = set(config["allowed_countries"])
    RATE_LIMIT = config["rate_limit"]
    RATE_WINDOW = config["rate_window"]

def packet_filter(source_ip, destination_port):
    """Filter packets based on IP, port, country, and rate-limit. Auto-reloads rules."""
    reload_rules()  # Reload rules before each check
    now = time.time()
    # Rate-limiting
    requests = ip_request_log[source_ip]
    # Remove timestamps outside window
    while requests and now - requests[0] > RATE_WINDOW:
        requests.popleft()
    if len(requests) >= RATE_LIMIT:
        print(f"🚨 BLOCKED: Rate limit exceeded for {source_ip}")
        log_traffic("BLOCKED-RATE", source_ip, destination_port)
        return False
    requests.append(now)

    # Geo-restriction
    country = get_country_from_ip(source_ip)
    if country and country not in ALLOWED_COUNTRIES:
        print(f"🚨 BLOCKED: Geo-restriction for {source_ip} ({country})")
        log_traffic("BLOCKED-GEO", source_ip, destination_port)
        return False
    # IP filtering
    if source_ip not in ALLOWED_IPS:
        log_traffic("BLOCKED", source_ip, destination_port)
        return detect_intrusion(source_ip)
    # Port filtering
    if destination_port in BLOCKED_PORTS:
        log_traffic("BLOCKED", source_ip, destination_port)
        return False
    log_traffic("ALLOWED", source_ip, destination_port)
    return True

# --- Simulated network packets (source IP, destination port) ---
packets = [
    ("192.168.1.1", 22),
    ("10.0.0.5", 23),
    ("192.168.1.2", 8080),
    ("10.0.0.10", 443),
    ("10.0.0.5", 22),
    ("10.0.0.5", 22),
    ("10.0.0.5", 22),
    ("10.0.0.5", 22)
]
for packet in packets:
    packet_filter(packet[0], packet[1])

if geoip_reader:
    geoip_reader.close()
conn.close()
