import socket
import threading
import pickle
import time
import os
import hashlib

LOG_FILE = os.path.join(os.path.dirname(__file__), 'dfss.log')


def log_event(ev: str):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{ts}] {ev}\n"
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(line)
    print(line, end='')


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


# storage structure: { filename: { 'total': int, 'chunks': { idx: bytes }, 'checksums': { idx: checksum } } }
storage = {}
store_lock = threading.Lock()


def handle_client(conn, addr):
    try:
        req = recv_msg(conn)
        if req is None:
            return
        rtype = req.get('type')

        if rtype == 'store_chunk':
            filename = req.get('filename')
            index = int(req.get('index'))
            total = int(req.get('total'))
            payload = req.get('payload')
            checksum = req.get('checksum')

            if compute_checksum(payload) != checksum:
                send_msg(conn, {'status': 'nack', 'reason': 'checksum_mismatch'})
                log_event(f"Rejected chunk {filename}[{index}] from {addr}: checksum mismatch")
                return

            with store_lock:
                meta = storage.setdefault(filename, {'total': total, 'chunks': {}, 'checksums': {}})
                meta['total'] = max(meta['total'], total)
                meta['chunks'][index] = payload
                meta['checksums'][index] = checksum

            send_msg(conn, {'status': 'stored'})
            log_event(f"Stored chunk {filename}[{index}] (total={total}) from {addr}")

        elif rtype == 'get_chunk':
            filename = req.get('filename')
            index = int(req.get('index'))
            with store_lock:
                meta = storage.get(filename)
                if not meta or index not in meta['chunks']:
                    send_msg(conn, {'status': 'miss'})
                    log_event(f"Chunk miss {filename}[{index}] requested by {addr}")
                    return
                payload = meta['chunks'][index]
                checksum = meta['checksums'].get(index)
            send_msg(conn, {'status': 'ok', 'payload': payload, 'checksum': checksum})
            log_event(f"Served chunk {filename}[{index}] to {addr}")

        elif rtype == 'get_file_info':
            filename = req.get('filename')
            with store_lock:
                meta = storage.get(filename)
                if not meta:
                    send_msg(conn, {'status': 'missing'})
                    log_event(f"File info request for missing {filename} from {addr}")
                    return
                total = int(meta['total'])
                available = sorted(list(meta['chunks'].keys()))
            send_msg(conn, {'status': 'ok', 'total': total, 'available': available})
            log_event(f"Provided file info for {filename} to {addr}: total={total} have={len(available)}")

        else:
            send_msg(conn, {'status': 'error', 'reason': 'unknown_type'})

    except Exception as e:
        log_event(f"Error handling client {addr}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def peer_server(host='0.0.0.0', port=9000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(8)
    log_event(f"DFSS Peer started on {host}:{port}")
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()


if __name__ == '__main__':
    peer_server()
