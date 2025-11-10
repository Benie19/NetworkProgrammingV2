import argparse
import gzip
import heapq
import io
import math
import socket
import threading
import time
import uuid
import logging
from collections import defaultdict

from low_bandwidth_protocol import (
    send_frame,
    pack_msg_header,
    COMP_GZIP,
    COMP_JPEG,
    COMP_NONE,
)

try:
    from PIL import Image
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')


def compress_data(path: str):
    b = open(path, 'rb').read()
    # Prefer Pillow-based detection and re-encoding when available.
    if PIL_AVAILABLE:
        try:
            img = Image.open(io.BytesIO(b))
            out = io.BytesIO()
            img.save(out, 'JPEG', quality=70)
            logging.info('Compressed image %s -> JPEG (lossy)', path)
            return out.getvalue(), COMP_JPEG
        except Exception:
            # Not an image (or Pillow failed to parse) — fall through to gzip.
            pass

    # If Pillow isn't available, use filename extension heuristic for images.
    lower = path.lower()
    if lower.endswith(('.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.webp')):
        logging.warning('Pillow not installed or could not parse image; sending raw image bytes and marking as JPEG')
        return b, COMP_JPEG

    # default: gzip compress
    comp = gzip.compress(b, mtime=0)
    logging.info('Gzip compressed %s: %d -> %d bytes', path, len(b), len(comp))
    return comp, COMP_GZIP


def split_into_shards(data: bytes, k: int):
    if k < 1:
        raise ValueError('k must be >=1')
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


def make_parity_shard(data_shards):
    # simple bytewise XOR parity across all data shards; recovers one missing shard
    if not data_shards:
        return b''
    length = len(data_shards[0])
    parity = bytearray(length)
    for s in data_shards:
        for i in range(length):
            parity[i] ^= s[i]
    return bytes(parity)


class Scheduler:
    def __init__(self, sock: socket.socket, bandwidth_limit_kbps: int = 0):
        self.sock = sock
        self.pq = []
        self.counter = 0
        self.lock = threading.Lock()
        self.bandwidth_limit_kbps = bandwidth_limit_kbps
        self.bytes_sent_in_window = 0
        self.window_start = time.time()
        self.log_file = 'lowbw_usage.log'
        # stats thread
        t = threading.Thread(target=self._stats_thread, daemon=True)
        t.start()

    def _stats_thread(self):
        while True:
            time.sleep(1)
            now = time.time()
            sent = 0
            with self.lock:
                sent = self.bytes_sent_in_window
                self.bytes_sent_in_window = 0
                self.window_start = now
            # append CSV: timestamp, bytes
            with open(self.log_file, 'a') as f:
                f.write(f"{int(now)},{sent}\n")

    def queue_shard(self, priority: int, msg_id: uuid.UUID, total_shards: int, shard_index: int, orig_len: int, flags: int, payload: bytes):
        with self.lock:
            self.counter += 1
            entry = (priority, self.counter, (msg_id, total_shards, shard_index, orig_len, flags, payload))
            heapq.heappush(self.pq, entry)

    def run(self):
        while True:
            with self.lock:
                if not self.pq:
                    next_item = None
                else:
                    next_item = heapq.heappop(self.pq)
            if not next_item:
                time.sleep(0.05)
                continue
            _, _, (msg_id, total_shards, shard_index, orig_len, flags, payload) = next_item
            hdr = pack_msg_header(flags, msg_id, total_shards, shard_index, orig_len)
            frame = hdr + payload
            # bandwidth limiting: if limit set, ensure we don't exceed per-second budget
            if self.bandwidth_limit_kbps > 0:
                kbps = self.bandwidth_limit_kbps
                budget = kbps * 1024 / 8  # bytes per second? actually kbps -> kilobits per second
                # convert to bytes/sec (kilobits -> bits): kbps*1000 bits/sec -> /8 bytes
                budget = kbps * 1000 / 8
                # wait until we have budget
                while True:
                    with self.lock:
                        elapsed = time.time() - self.window_start
                        if elapsed >= 1:
                            # window will be reset by stats thread soon; allow send
                            break
                        if self.bytes_sent_in_window + len(frame) <= budget:
                            break
                    time.sleep(0.05)
            try:
                send_frame(self.sock, frame)
                with self.lock:
                    self.bytes_sent_in_window += len(frame)
                logging.info('Sent shard %d/%d for %s (%d bytes)', shard_index, total_shards, msg_id.hex[:8], len(payload))
            except Exception as e:
                logging.exception('Failed to send shard %s: %s', msg_id.hex[:8], e)
                # on failure, requeue with slight backoff
                time.sleep(0.2)
                self.queue_shard(1, msg_id, total_shards, shard_index, orig_len, flags, payload)


def send_file(path: str, host: str, port: int, priority: int, data_shards: int, parity_shards: int, bandwidth_limit_kbps: int):
    data, flags = compress_data(path)
    orig_len = len(open(path, 'rb').read())
    k = max(1, data_shards)
    p = max(0, parity_shards)
    total_shards = k + p
    shards = split_into_shards(data, k)
    parity = make_parity_shard(shards) if p >= 1 else None
    sock = socket.create_connection((host, port))
    sched = Scheduler(sock, bandwidth_limit_kbps)
    t = threading.Thread(target=sched.run, daemon=True)
    t.start()
    msg_id = uuid.uuid4()
    # queue data shards
    for i, s in enumerate(shards):
        sched.queue_shard(priority, msg_id, total_shards, i, orig_len, flags, s)
    if parity is not None:
        # place parity as last shard index k
        sched.queue_shard(priority + 1, msg_id, total_shards, k, orig_len, flags, parity)

    # wait until queue empty
    while True:
        with sched.lock:
            empty = not sched.pq
        if empty:
            break
        time.sleep(0.1)
    logging.info('All shards queued and sent (or attempted) for %s', msg_id.hex[:8])
    sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', '-f', required=True)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=9009)
    parser.add_argument('--priority', type=int, default=1, help='0=urgent, higher=lower priority')
    parser.add_argument('--data-shards', type=int, default=4)
    parser.add_argument('--parity-shards', type=int, default=1)
    parser.add_argument('--bandwidth-kbps', type=int, default=0, help='0=unlimited')
    args = parser.parse_args()
    send_file(args.file, args.host, args.port, args.priority, args.data_shards, args.parity_shards, args.bandwidth_kbps)


if __name__ == '__main__':
    main()
