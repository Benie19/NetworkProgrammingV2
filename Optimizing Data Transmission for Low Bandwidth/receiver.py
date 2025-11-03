
import socket
import threading
import uuid
import gzip
import io
import logging
from collections import defaultdict

from low_bandwidth_protocol import (
    recv_frame,
    unpack_msg_header,
    COMP_GZIP,
    COMP_JPEG,
    COMP_NONE,
)

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')


class MsgState:
    def __init__(self, total_shards, orig_len, flags):
        self.total_shards = total_shards
        self.orig_len = orig_len
        self.flags = flags
        self.shards = {}
        self.parity = None


def reconstruct_and_write(msg_id: uuid.UUID, state: MsgState):
    k = state.total_shards - (1 if state.parity is not None else 0)
    data_shards = [state.shards.get(i) for i in range(k)]
    missing = [i for i, s in enumerate(data_shards) if s is None]
    if len(missing) == 0:
        # full
        full = b''.join(data_shards)
    elif len(missing) == 1 and state.parity is not None:
        # recover via parity
        idx = missing[0]
        shard_len = len(state.parity)
        recovered = bytearray(shard_len)
        for i in range(k):
            if i == idx:
                continue
            s = data_shards[i]
            for j in range(shard_len):
                recovered[j] ^= s[j]
        for j in range(shard_len):
            recovered[j] ^= state.parity[j]
        data_shards[idx] = bytes(recovered)
        full = b''.join(data_shards)
    else:
        logging.warning('Cannot reconstruct %s: missing shards %s', msg_id.hex[:8], missing)
        return False

    # trim to original compressed length heuristically using orig_len? orig_len is original uncompressed length
    # For compressed data we don't have exact compressed length; remove trailing zero padding
    full = full.rstrip(b'\x00')

    # decompress if needed
    flags = state.flags
    if flags & 0x0F == COMP_GZIP:
        try:
            out = gzip.decompress(full)
            ext = 'bin'
            data_to_write = out
        except Exception:
            logging.exception('gzip decompress failed for %s', msg_id.hex[:8])
            return False
    elif flags & 0x0F == COMP_JPEG:
        # JPEG bytes already
        data_to_write = full
        ext = 'jpg'
    else:
        data_to_write = full
        ext = 'bin'

    filename = f'recv_{msg_id.hex[:8]}.{ext}'
    with open(filename, 'wb') as f:
        f.write(data_to_write)
    logging.info('Wrote reconstructed file %s (%d bytes)', filename, len(data_to_write))
    return True


def handle_client(conn: socket.socket, addr):
    logging.info('Client connected: %s', addr)
    states = defaultdict(lambda: None)
    try:
        while True:
            frame = recv_frame(conn)
            # parse header then payload
            from low_bandwidth_protocol import MSG_HDR
            hdr_size = MSG_HDR.size
            if len(frame) < hdr_size:
                logging.warning('Frame too short from %s', addr)
                continue
            version, flags, msg_id, total_shards, shard_index, orig_len = unpack_msg_header(frame[:hdr_size])
            payload = frame[hdr_size:]
            sid = msg_id
            if states.get(sid) is None:
                st = MsgState(total_shards, orig_len, flags)
                states[sid] = st
            else:
                st = states[sid]
            # detect parity shard index (we put parity as last index if present)
            data_shards_count = total_shards
            # if shard_index == data_shards_count - 1 and len(st.shards) < total_shards - 1:
            # store parity separately if it appears to be the parity
            # For our sender parity index = k (data_shards k then parity at index k)
            # We'll treat any shard index >= (total_shards - 1) as parity
            # Heuristic: if shard_index >= total_shards - 1 and len(payload) > 0:
            if shard_index >= total_shards - 1:
                st.parity = payload
                logging.info('Received parity shard for %s', sid.hex[:8])
            else:
                st.shards[shard_index] = payload
                logging.info('Received data shard %d/%d for %s', shard_index, total_shards, sid.hex[:8])

            # check if we can reconstruct
            data_present = sum(1 for i in range(total_shards) if i in st.shards)
            if st.parity is not None:
                if data_present >= total_shards - 1:
                    # attempt reconstruction
                    success = reconstruct_and_write(sid, st)
                    if success:
                        del states[sid]
            else:
                if data_present >= total_shards:
                    success = reconstruct_and_write(sid, st)
                    if success:
                        del states[sid]

    except ConnectionError:
        logging.info('Client disconnected: %s', addr)
    except Exception:
        logging.exception('Error handling client %s', addr)
    finally:
        conn.close()


def serve(host='0.0.0.0', port=9009):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(8)
    logging.info('Receiver listening on %s:%d', host, port)
    try:
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    finally:
        s.close()


if __name__ == '__main__':
    serve()
