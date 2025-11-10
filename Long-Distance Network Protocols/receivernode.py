import socket
import pickle
import struct
import uuid
import gzip
import logging
from collections import defaultdict
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES

FRAME_HDR = struct.Struct('>I')


def send_frame(sock, data: bytes):
    sock.sendall(FRAME_HDR.pack(len(data)) + data)


def recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('socket closed')
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock):
    hdr = recv_exact(sock, FRAME_HDR.size)
    (length,) = FRAME_HDR.unpack(hdr)
    return recv_exact(sock, length)


def derive_key(passphrase: str) -> bytes:
    return PBKDF2(passphrase, b'salt-long-distance', dkLen=32, count=100_000)


def decrypt_blob(key: bytes, blob: bytes) -> bytes:
    if len(blob) >= 28:
        nonce = blob[:12]
        tag = blob[12:28]
        ct = blob[28:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ct, tag)
    return blob


def reconstruct(shards: dict, total_shards: int) -> bytes:
    # assume last shard may be parity if len(shards)==total_shards or total_shards-1
    k = total_shards
    # build list for data shards (if parity present, last index is parity)
    indices = sorted(shards.keys())
    # if parity present, detect by max index >= total_shards-1
    if max(indices) >= total_shards - 1:
        # parity at index == total_shards - 1
        k = total_shards - 1
    data_shards = [shards.get(i) for i in range(k)]
    missing = [i for i, s in enumerate(data_shards) if s is None]
    if len(missing) == 0:
        full = b''.join(data_shards)
    elif len(missing) == 1 and (total_shards - k) >= 1:
        parity = shards.get(k)
        shard_len = len(parity)
        recovered = bytearray(shard_len)
        for i in range(k):
            if i == missing[0]:
                continue
            s = data_shards[i]
            for j in range(shard_len):
                recovered[j] ^= s[j]
        for j in range(shard_len):
            recovered[j] ^= parity[j]
        data_shards[missing[0]] = bytes(recovered)
        full = b''.join(data_shards)
    else:
        raise ValueError('cannot reconstruct, missing shards: %s' % missing)
    return full.rstrip(b'\x00')


def fetch_messages(relay_host='127.0.0.1', relay_port=9000, dest=None, passphrase='demo'):
    key = derive_key(passphrase)
    s = socket.create_connection((relay_host, relay_port))
    try:
        req = {'type': 'fetch', 'dest': dest}
        send_frame(s, pickle.dumps(req))
        messages = defaultdict(lambda: {'shards': {}, 'total': None})
        while True:
            try:
                frame = recv_frame(s)
            except ConnectionError:
                break
            pkt = pickle.loads(frame)
            if pkt.get('type') == 'shard':
                mid = pkt['msg_id']
                idx = pkt['shard_index']
                total = pkt['total_shards']
                enc = pkt['payload']
                data = decrypt_blob(key, enc)
                messages[mid]['shards'][idx] = data
                messages[mid]['total'] = total
                # attempt reconstruction when possible
                try:
                    full = reconstruct(messages[mid]['shards'], messages[mid]['total'])
                    # write to file
                    fname = f'recv_{mid[:8]}.bin'
                    with open(fname, 'wb') as f:
                        f.write(full)
                    print('Wrote', fname)
                    del messages[mid]
                except Exception:
                    # not ready yet
                    pass
    finally:
        s.close()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--relay-host', default='127.0.0.1')
    parser.add_argument('--relay-port', type=int, default=9000)
    parser.add_argument('--dest', default=None)
    parser.add_argument('--pass', dest='pw', default='demo')
    args = parser.parse_args()
    fetch_messages(args.relay_host, args.relay_port, dest=args.dest, passphrase=args.pw)