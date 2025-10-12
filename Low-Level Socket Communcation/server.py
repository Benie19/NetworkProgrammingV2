import socket
import struct
import json

# Message type constants
MESSAGE_TYPE_TEXT = 1
MESSAGE_TYPE_SENSOR = 2
MESSAGE_TYPE_ALERT = 3

def handle_text_message(payload):
    """Handle text message type"""
    message = payload.decode('utf-8')
    print(f" Text Message: {message}")
    return f"Text received: {message}"

def handle_sensor_data(payload):
    """Handle sensor data message type"""
    try:
        # Sensor data format: temperature (float), humidity (float), timestamp (int)
        temperature, humidity, timestamp = struct.unpack('ffi', payload)
        print(f" Sensor Data - Temperature: {temperature:.2f}°C, Humidity: {humidity:.2f}%, Timestamp: {timestamp}")
        return f"Sensor data logged: T={temperature:.2f}°C, H={humidity:.2f}%"
    except struct.error:
        print("❌ Invalid sensor data format")
        return "Error: Invalid sensor data"

def handle_alert_message(payload):
    """Handle alert message type"""
    try:
        # Alert format: priority (1 byte), message (rest as string)
        priority = struct.unpack('B', payload[:1])[0]
        alert_message = payload[1:].decode('utf-8')
        priority_levels = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
        priority_str = priority_levels.get(priority, "UNKNOWN")
        print(f" Alert [{priority_str}]: {alert_message}")
        return f"Alert acknowledged: [{priority_str}] {alert_message}"
    except (struct.error, UnicodeDecodeError):
        print(" Invalid alert format")
        return "Error: Invalid alert format"

def process_message(message_type, payload):
    """Process message based on type"""
    if message_type == MESSAGE_TYPE_TEXT:
        return handle_text_message(payload)
    elif message_type == MESSAGE_TYPE_SENSOR:
        return handle_sensor_data(payload)
    elif message_type == MESSAGE_TYPE_ALERT:
        return handle_alert_message(payload)
    else:
        print(f" Unknown message type: {message_type}")
        return f"Error: Unknown message type {message_type}"

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", 12345))
    server_socket.listen(5)
    print(" Server waiting for connections on port 12345...")
    
    try:
        while True:
            conn, addr = server_socket.accept()
            print(f" Connected to {addr}")
            
            try:
                # Read message type (1 byte)
                type_data = conn.recv(1)
                if not type_data:
                    print(" No data received")
                    continue
                    
                message_type = struct.unpack('B', type_data)[0]
                print(f" Message Type: {message_type}")
                
                # Read message length (4 bytes)
                length_data = conn.recv(4)
                if len(length_data) != 4:
                    print(" Invalid header length")
                    continue
                    
                message_length = struct.unpack('I', length_data)[0]
                print(f" Message Length: {message_length} bytes")
                
                # Read message payload
                payload = b""
                bytes_received = 0
                while bytes_received < message_length:
                    chunk = conn.recv(min(4096, message_length - bytes_received))
                    if not chunk:
                        break
                    payload += chunk
                    bytes_received += len(chunk)
                
                if len(payload) != message_length:
                    print(f" Expected {message_length} bytes, got {len(payload)}")
                    continue
                
                # Process the message
                response = process_message(message_type, payload)
                
                # Send response back to client
                response_bytes = response.encode('utf-8')
                response_header = struct.pack('BI', MESSAGE_TYPE_TEXT, len(response_bytes))
                conn.sendall(response_header + response_bytes)
                
            except Exception as e:
                print(f" Error processing message: {e}")
            finally:
                conn.close()
                print(" Connection closed\n")
                
    except KeyboardInterrupt:
        print("\n Server shutting down...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()