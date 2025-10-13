import socket
import json
import time
import gzip
import msgpack
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

# Mission data
mission_status = {
    "rover_id": "Perseverance",
    "battery": 85,
    "location": [45.123, -93.456],
    "status": "Exploring"
}

# Network config
HOST = "0.0.0.0"
PORT = 5000

# Encryption config (derive 256-bit key)
PASSWORD = b"hello-password"
SALT = b"salt1234"
KEY = PBKDF2(PASSWORD, SALT, dkLen=32, count=100_000)


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-GCM encrypt. Returns blob = iv(16) + tag(16) + ciphertext."""
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return iv + tag + ciphertext


def make_protobuf_serializer():
    """Dynamically defines a 'Mission' message for protobuf v6+."""

    file_desc_proto = descriptor_pb2.FileDescriptorProto()
    file_desc_proto.name = "mission.proto"
    msg = file_desc_proto.message_type.add()
    msg.name = "Mission"

    # Define message fields
    def add_field(name, number, label, ftype):
        f = msg.field.add()
        f.name = name
        f.number = number
        f.label = label
        f.type = ftype

    add_field("rover_id", 1, descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL,
              descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
    add_field("battery", 2, descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL,
              descriptor_pb2.FieldDescriptorProto.TYPE_INT32)
    add_field("location", 3, descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED,
              descriptor_pb2.FieldDescriptorProto.TYPE_DOUBLE)
    add_field("status", 4, descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL,
              descriptor_pb2.FieldDescriptorProto.TYPE_STRING)

    pool = descriptor_pool.Default()
    pool.Add(file_desc_proto)
    desc = pool.FindMessageTypeByName("Mission")

    # ✅ protobuf 6.x way
    MissionMessage = message_factory.GetMessageClass(desc)

    def serialize(obj: dict) -> bytes:
        m = MissionMessage()
        m.rover_id = obj.get("rover_id", "")
        m.battery = int(obj.get("battery", 0))
        m.location.extend([float(x) for x in obj.get("location", [])])
        m.status = obj.get("status", "")
        return m.SerializeToString()

    def deserialize(blob: bytes) -> dict:
        m = MissionMessage()
        m.ParseFromString(blob)
        return {
            "rover_id": m.rover_id,
            "battery": m.battery,
            "location": list(m.location),
            "status": m.status,
        }

    return serialize, deserialize


# Serializers
json_serialize = lambda o: json.dumps(o).encode("utf-8")
msgpack_serialize = lambda o: msgpack.packb(o, use_bin_type=True)
proto_serialize, proto_deserialize = make_protobuf_serializer()


def compress_gzip(data: bytes) -> bytes:
    return gzip.compress(data)


def send_packet(conn, method_name: str, payload: bytes):
    """Send method header + payload."""
    header = {"method": method_name, "payload_size": len(payload)}
    header_json = json.dumps(header).encode("utf-8")
    header_len = len(header_json).to_bytes(4, "big")
    conn.sendall(header_len + header_json + payload)


def prepare_and_send(conn, method: str, obj: dict):
    """Serialize, compress, encrypt, and send."""
    # serialize
    t0 = time.time()
    if method == "json":
        serialized = json_serialize(obj)
    elif method == "msgpack":
        serialized = msgpack_serialize(obj)
    elif method == "protobuf":
        serialized = proto_serialize(obj)
    else:
        raise ValueError("Unknown method")
    t1 = time.time()
    print(f"[{method}] raw size: {len(serialized)} bytes ({(t1-t0)*1000:.2f} ms)")

    # compress
    t0 = time.time()
    compressed = compress_gzip(serialized)
    t1 = time.time()
    print(f"[{method}] compressed size: {len(compressed)} bytes ({(t1-t0)*1000:.2f} ms)")

    # encrypt
    t0 = time.time()
    encrypted = aes_encrypt(KEY, compressed)
    t1 = time.time()
    print(f"[{method}] encrypted size: {len(encrypted)} bytes ({(t1-t0)*1000:.2f} ms)")

    # send
    t0 = time.time()
    send_packet(conn, method, encrypted)
    t1 = time.time()
    print(f"[{method}] sent in {(t1-t0)*1000:.2f} ms\n")

    return {
        "raw_size": len(serialized),
        "compressed_size": len(compressed),
        "encrypted_size": len(encrypted),
    }


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print(f"Server listening on {HOST}:{PORT}")

    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")

    for method in ("json", "msgpack", "protobuf"):
        prepare_and_send(conn, method, mission_status)
        time.sleep(0.25)

    conn.close()
    server_socket.close()


if __name__ == "__main__":
    main()
