import socket
import struct
import time
import random

# Message type constants
MESSAGE_TYPE_TEXT = 1
MESSAGE_TYPE_SENSOR = 2
MESSAGE_TYPE_ALERT = 3

def send_message(sock, message_type, payload):
    """Send a message with the custom binary protocol"""
    # Pack message type (1 byte) + message length (4 bytes) + payload
    header = struct.pack('BI', message_type, len(payload))
    sock.sendall(header + payload)

def send_text_message(sock, text):
    """Send a text message"""
    print(f"📝 Sending text message: {text}")
    payload = text.encode('utf-8')
    send_message(sock, MESSAGE_TYPE_TEXT, payload)

def send_sensor_data(sock, temperature, humidity, timestamp=None):
    """Send sensor data"""
    if timestamp is None:
        timestamp = int(time.time())
    
    print(f"🌡️ Sending sensor data: T={temperature:.2f}°C, H={humidity:.2f}%, Time={timestamp}")
    # Pack as: temperature (float), humidity (float), timestamp (int)
    payload = struct.pack('ffi', temperature, humidity, timestamp)
    send_message(sock, MESSAGE_TYPE_SENSOR, payload)

def send_alert_message(sock, priority, alert_text):
    """Send an alert message"""
    priority_levels = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
    priority_str = priority_levels.get(priority, "UNKNOWN")
    
    print(f"🚨 Sending alert [{priority_str}]: {alert_text}")
    # Pack as: priority (1 byte) + alert message (string)
    payload = struct.pack('B', priority) + alert_text.encode('utf-8')
    send_message(sock, MESSAGE_TYPE_ALERT, payload)

def receive_response(sock):
    """Receive and decode server response"""
    try:
        # Read response header
        type_data = sock.recv(1)
        length_data = sock.recv(4)
        
        if not type_data or not length_data:
            return None
            
        response_type = struct.unpack('B', type_data)[0]
        response_length = struct.unpack('I', length_data)[0]
        
        # Read response payload
        response_payload = sock.recv(response_length)
        response_message = response_payload.decode('utf-8')
        
        print(f"✅ Server response: {response_message}\n")
        return response_message
        
    except Exception as e:
        print(f"❌ Error receiving response: {e}")
        return None

def demo_client():
    """Demonstrate different message types"""
    
    # Example 1: Text Message
    print("=" * 50)
    print("📝 SENDING TEXT MESSAGE")
    print("=" * 50)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", 12345))
        
        send_text_message(sock, "Hello from Mars! This is a text message.")
        receive_response(sock)
        sock.close()
    except Exception as e:
        print(f"❌ Error: {e}")
    
    time.sleep(1)
    
    # Example 2: Sensor Data
    print("=" * 50)
    print("🌡️ SENDING SENSOR DATA")
    print("=" * 50)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", 12345))
        
        # Simulate sensor readings
        temp = 23.5 + random.uniform(-5, 5)  # Random temperature
        humidity = 65.0 + random.uniform(-10, 10)  # Random humidity
        send_sensor_data(sock, temp, humidity)
        receive_response(sock)
        sock.close()
    except Exception as e:
        print(f"❌ Error: {e}")
    
    time.sleep(1)
    
    # Example 3: Alert Message
    print("=" * 50)
    print("🚨 SENDING ALERT MESSAGE")
    print("=" * 50)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", 12345))
        
        send_alert_message(sock, 3, "Temperature threshold exceeded!")
        receive_response(sock)
        sock.close()
    except Exception as e:
        print(f"❌ Error: {e}")

def interactive_client():
    """Interactive client for testing"""
    print("\n🎮 Interactive Mode")
    print("Commands: text, sensor, alert, demo, quit")
    
    while True:
        command = input("\nEnter command: ").strip().lower()
        
        if command == "quit":
            break
        elif command == "demo":
            demo_client()
        elif command == "text":
            message = input("Enter text message: ")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(("127.0.0.1", 12345))
                send_text_message(sock, message)
                receive_response(sock)
                sock.close()
            except Exception as e:
                print(f"❌ Error: {e}")
                
        elif command == "sensor":
            try:
                temp = float(input("Enter temperature: "))
                humidity = float(input("Enter humidity: "))
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(("127.0.0.1", 12345))
                send_sensor_data(sock, temp, humidity)
                receive_response(sock)
                sock.close()
            except (ValueError, Exception) as e:
                print(f"❌ Error: {e}")
                
        elif command == "alert":
            try:
                priority = int(input("Enter priority (1-4): "))
                message = input("Enter alert message: ")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(("127.0.0.1", 12345))
                send_alert_message(sock, priority, message)
                receive_response(sock)
                sock.close()
            except (ValueError, Exception) as e:
                print(f"❌ Error: {e}")
        else:
            print("❓ Unknown command. Use: text, sensor, alert, demo, quit")

if __name__ == "__main__":
    print("🚀 Client starting...")
    print("Choose mode:")
    print("1. Demo mode (automatic examples)")
    print("2. Interactive mode")
    
    choice = input("Enter choice (1 or 2): ").strip()
    
    if choice == "1":
        demo_client()
    else:
        interactive_client()