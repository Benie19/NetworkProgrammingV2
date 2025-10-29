import socket
import pickle
import sys
import os
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


def send_msg(conn, obj):
    data = pickle.dumps(obj)
    conn.sendall(len(data).to_bytes(4, 'big') + data)


def recv_msg(conn):
    len_b = conn.recv(4)
    if not len_b:
        return None
    total = int.from_bytes(len_b, 'big')
    chunks = bytearray()
    while len(chunks) < total:
        chunk = conn.recv(min(4096, total - len(chunks)))
        if not chunk:
            raise ConnectionError('socket closed')
        chunks.extend(chunk)
    return pickle.loads(bytes(chunks))


def compute_checksum(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def ask_for_file_info(peer, filename, timeout=5):
    host, port = peer
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            send_msg(s, {'type': 'get_file_info', 'filename': filename})
            resp = recv_msg(s)
            return resp
    except Exception:
        return None


def fetch_chunk_from_peer(peer, filename, index, max_attempts=4):
    host, port = peer
    attempt = 0
    backoff = 0.5
    while attempt < max_attempts:
        attempt += 1
        try:
            with socket.create_connection((host, port), timeout=6) as s:
                send_msg(s, {'type': 'get_chunk', 'filename': filename, 'index': index})
                resp = recv_msg(s)
                if resp and resp.get('status') == 'ok':
                    payload = resp.get('payload')
                    checksum = resp.get('checksum')
                    if compute_checksum(payload) != checksum:
                        print(f"Checksum mismatch for {filename}[{index}] from {host}:{port}")
                        raise ValueError('checksum')
                    return {'status': 'ok', 'payload': payload, 'peer': peer}
                else:
                    # miss or other
                    raise ConnectionError('miss')
        except Exception as e:
            print(f"Attempt {attempt} failed for chunk {index} from {host}:{port}: {e}")
            time.sleep(backoff)
            backoff *= 1.8
    return {'status': 'failed', 'peer': peer}


def download(filename, peers, out_path=None, max_workers=8):
    # Ask peers for file info
    info = None
    for p in peers:
        resp = ask_for_file_info(p, filename)
        if resp and resp.get('status') == 'ok':
            info = resp
            print(f"Peer {p} reports total={info['total']} available={len(info['available'])}")
            break

    if not info:
        print('Could not determine file info from peers')
        return False

    total = int(info['total'])
    out_path = Path(out_path or filename)
    # container for chunks
    chunks = [None] * total

    # build list of tasks (index -> try fetch from many peers until success)
    indices = list(range(total))

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {}
        for idx in indices:
            # initial try: schedule fetching from peers in round-robin order
            peer = peers[idx % len(peers)]
            futures[ex.submit(fetch_chunk_from_peer, peer, filename, idx)] = idx

        completed = 0
        while futures:
            done, _ = as_completed(futures), None
            for fut in done:
                idx = futures.pop(fut)
                try:
                    res = fut.result()
                except Exception as e:
                    res = {'status': 'failed'}
                if res.get('status') == 'ok':
                    chunks[idx] = res.get('payload')
                    completed += 1
                    print(f"Got chunk {idx} from {res.get('peer')}")
                else:
                    # schedule another attempt from a different peer
                    # choose next peer and resubmit
                    next_peer = peers[(idx + 1) % len(peers)]
                    if next_peer == res.get('peer'):
                        # rotate further if same
                        next_peer = peers[(idx + 2) % len(peers)]
                    futures[ex.submit(fetch_chunk_from_peer, next_peer, filename, idx)] = idx

    if any(c is None for c in chunks):
        print('Failed to fetch all chunks')
        return False

    with open(out_path, 'wb') as f:
        for c in chunks:
            f.write(c)

    print(f"Reassembled file to {out_path}")
    return True


def parse_peers(peers_str):
    out = []
    for item in peers_str.split(','):
        host, port = item.split(':')
        out.append((host, int(port)))
    return out


def main():
    if len(sys.argv) < 3:
        print("Usage: dfss_downloader.py <filename> <peer1:port,peer2:port,...> [out_path]")
        return
    filename = sys.argv[1]
    peers = parse_peers(sys.argv[2])
    out = sys.argv[3] if len(sys.argv) >= 4 else None
    success = download(filename, peers, out_path=out)
    if success:
        print('Download complete')
    else:
        print('Download failed')


if __name__ == '__main__':
    main()
