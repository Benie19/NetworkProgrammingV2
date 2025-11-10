import argparse
import socket
import pickle
import uuid
import math
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import struct

FRAME_HDR = struct.Struct('>I')


def send_frame(sock, data: bytes):
    sock.sendall(FRAME_HDR.pack(len(data)) + data)


def derive_key(passphrase: str) -> bytes:
    return PBKDF2(passphrase, b'salt-long-distance', dkLen=32, count=100_000)


def encrypt_blob(key: bytes, plaintext: bytes) -> bytes:
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ct


def split_into_shards(data: bytes, k: int):
    if k < 1:
        raise ValueError('k>=1')
    shard_size = math.ceil(len(data) / k)
    shards = []
    for i in range(k):
        start = i * shard_size
        end = start + shard_size
        chunk = data[start:end]
        if len(chunk) < shard_size:
            chunk = chunk + b'\x00' * (shard_size - len(chunk))
        shards.append(chunk)
    return shards


def make_parity(shards):
    if not shards:
        return b''
    length = len(shards[0])
    parity = bytearray(length)
    for s in shards:
        for i in range(length):
            parity[i] ^= s[i]
    return bytes(parity)


def send_sharded_message(relay_host, relay_port, dest, data: bytes, passphrase: str, data_shards=4, parity_shards=1, priority=1):
    key = derive_key(passphrase)
    k = max(1, data_shards)
    p = max(0, parity_shards)
    shards = split_into_shards(data, k)
    parity = make_parity(shards) if p >= 1 else None
    total = k + (1 if parity is not None else 0)
    msg_id = uuid.uuid4().hex
    s = socket.create_connection((relay_host, relay_port))
    try:
        # send each shard as a store_shard packet
        for i, sh in enumerate(shards):
            enc = encrypt_blob(key, sh)
            pkt = {'type': 'store_shard', 'msg_id': msg_id, 'shard_index': i, 'total_shards': total, 'priority': priority, 'dest': dest, 'payload': enc}
            send_frame(s, pickle.dumps(pkt))
        if parity is not None:
            enc = encrypt_blob(key, parity)
            pkt = {'type': 'store_shard', 'msg_id': msg_id, 'shard_index': k, 'total_shards': total, 'priority': priority, 'dest': dest, 'payload': enc}
            send_frame(s, pickle.dumps(pkt))
    finally:
        s.close()
    print(f'Sent message {msg_id[:8]} to relay {relay_host}:{relay_port} (shards={total})')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--relay-host', default='127.0.0.1')
    parser.add_argument('--relay-port', type=int, default=9000)
    parser.add_argument('--dest', required=True)
    parser.add_argument('--file', help='file to send; if omitted reads stdin')
    parser.add_argument('--pass', dest='pw', default='demo')
    parser.add_argument('--data-shards', type=int, default=4)
    parser.add_argument('--parity-shards', type=int, default=1)
    parser.add_argument('--priority', type=int, default=1)
    args = parser.parse_args()
    if args.file:
        data = open(args.file, 'rb').read()
    else:
        import sys
        data = sys.stdin.buffer.read()
    send_sharded_message(args.relay_host, args.relay_port, args.dest, data, args.pw, data_shards=args.data_shards, parity_shards=args.parity_shards, priority=args.priority)