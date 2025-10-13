import socket
import json
import time
import gzip
import msgpack
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

# Must match server
PASSWORD = b"hello-password"
SALT = b"salt1234"
KEY = PBKDF2(PASSWORD, SALT, dkLen=32, count=100_000)


def aes_decrypt(key: bytes, blob: bytes) -> bytes:
    """Decrypt AES-GCM blob = iv(16) + tag(16) + ciphertext."""
    iv = blob[:16]
    tag = blob[16:32]
    ciphertext = blob[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


def decompress_gzip(b: bytes) -> bytes:
    return gzip.decompress(b)


def make_protobuf_deserializer():
    """Defines a protobuf 'Mission' message dynamically (protobuf 6.x)."""
    file_desc_proto = descriptor_pb2.FileDescriptorProto()
    file_desc_proto.name = "mission.proto"
    msg = file_desc_proto.message_type.add()
    msg.name = "Mission"

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
    MissionMessage = message_factory.GetMessageClass(desc)

    def deserialize_to_dict(blob: bytes) -> dict:
        m = MissionMessage()
        m.ParseFromString(blob)
        return {
            "rover_id": m.rover_id,
            "battery": m.battery,
            "location": list(m.location),
            "status": m.status,
        }

    return deserialize_to_dict


proto_deserialize = make_protobuf_deserializer()


def recv_exact(sock, nbytes):
    data = b""
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise ConnectionError("socket closed")
        data += chunk
    return data


def handle_single_message(conn):
    t_total_start = time.time()
    header_len_b = recv_exact(conn, 4)
    header_len = int.from_bytes(header_len_b, "big")

    header_json = recv_exact(conn, header_len)
    header = json.loads(header_json.decode("utf-8"))
    method = header.get("method")
    payload_size = header.get("payload_size")

    encrypted = recv_exact(conn, payload_size)

    metrics = {"received_encrypted_size": len(encrypted), "header": header}

    t0 = time.time()
    compressed = aes_decrypt(KEY, encrypted)
    t1 = time.time()
    metrics["decryption_ms"] = (t1 - t0) * 1000
    metrics["compressed_size"] = len(compressed)

    t0 = time.time()
    raw = decompress_gzip(compressed)
    t1 = time.time()
    metrics["decompression_ms"] = (t1 - t0) * 1000
    metrics["raw_size"] = len(raw)

    t0 = time.time()
    if method == "json":
        deserialized = json.loads(raw.decode("utf-8"))
    elif method == "msgpack":
        deserialized = msgpack.unpackb(raw, raw=False)
    elif method == "protobuf":
        deserialized = proto_deserialize(raw)
    else:
        raise ValueError("Unknown method: " + str(method))
    t1 = time.time()
    metrics["deserialization_ms"] = (t1 - t0) * 1000
    t_total_end = time.time()
    metrics["total_roundtrip_ms"] = (t_total_end - t_total_start) * 1000

    return method, deserialized, metrics


def main():
    HOST = "127.0.0.1"
    PORT = 5000
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"Connecting to {HOST}:{PORT} ...")
    sock.connect((HOST, PORT))
    print("Connected. Receiving messages...\n")

    summary = []
    try:
        for _ in range(3):
            method, data_dict, metrics = handle_single_message(sock)
            print(f"--- Received [{method}] ---")
            print("Decoded dict:", data_dict)
            print(json.dumps(metrics, indent=2), "\n")
            summary.append((method, metrics))
    except Exception as e:
        print("Error:", e)
    finally:
        sock.close()

    print("=== Comparative summary ===")
    for method, m in summary:
        print(f"{method:8} | encrypted {m['received_encrypted_size']:6} B | compressed {m['compressed_size']:6} B | raw {m['raw_size']:6} B | total {m['total_roundtrip_ms']:.2f} ms")


if __name__ == "__main__":
    main()
