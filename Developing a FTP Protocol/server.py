"""
Server that responds to a simple GET request:
Client must send: b"GET <filename>\n"

Server will:
 - compress <filename> into a temporary gzip file on disk
 - compute total_chunks for the compressed file
 - send chunked compressed data using the same header format:
     struct.pack("!II2s", chunk_number, total_chunks, checksum)
   where checksum is first 2 bytes of MD5 of the chunk (keeps compatibility
   with the client you provided).
 - wait for b"ACK" after each chunk, retransmit up to N retries on failure.
 - remove temporary gzip file at the end.

This keeps memory usage low for large files (only one compressed chunk is read into memory at a time).
"""
import socket
import struct
import hashlib
import os
import gzip
import tempfile
from pathlib import Path

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5500
CHUNK_SIZE = 1024
RETRANSMIT_RETRIES = 5

def compute_checksum(data: bytes) -> bytes:
    """Return first 2 bytes of MD5 of data (keeps compatibility with client)."""
    return hashlib.md5(data).digest()[:2]

def compress_file_to_gzip(src_path: str, gz_path: str):
    """Compress src_path -> gz_path using gzip streaming (file-based)."""
    with open(src_path, "rb") as src, gzip.open(gz_path, "wb") as gz:
        while True:
            chunk = src.read(64 * 1024)
            if not chunk:
                break
            gz.write(chunk)
    # gzip.close() will be called by context manager; file is on disk now

def send_file_in_chunks(conn: socket.socket, gz_path: str):
    """Send gz_path in CHUNK_SIZE chunks with header+checksum and wait for ACKs."""
    total_size = os.path.getsize(gz_path)
    total_chunks = (total_size + CHUNK_SIZE - 1) // CHUNK_SIZE

    print(f"Compressed size: {total_size} bytes -> total_chunks: {total_chunks}")

    with open(gz_path, "rb") as gz:
        for chunk_number in range(total_chunks):
            chunk = gz.read(CHUNK_SIZE)
            if not chunk:
                # Safety: if we read less unexpectedly, break
                print("No more data while sending - unexpected end")
                break

            checksum = compute_checksum(chunk)
            header = struct.pack("!II2s", chunk_number, total_chunks, checksum)

            # send header + chunk
            conn.sendall(header + chunk)

            # wait for ACK
            ack = conn.recv(1024)
            retries = RETRANSMIT_RETRIES
            while ack != b"ACK" and retries > 0:
                print(f"Retransmitting chunk {chunk_number}. Retries left: {retries}")
                conn.sendall(header + chunk)
                ack = conn.recv(1024)
                retries -= 1

            if retries == 0 and ack != b"ACK":
                print(f"Failed to send chunk {chunk_number} after retries. Aborting transfer.")
                return False

            print(f"Sent chunk {chunk_number}/{total_chunks - 1} (size {len(chunk)}).")

    return True

def handle_client(conn: socket.socket, addr):
    print(f"Connected: {addr}")
    try:
        # Expect a small initial command like "GET filename\n" or "GET filename"
        req = b""
        # read until newline or 1024 bytes (simple protocol)
        while b"\n" not in req and len(req) < 1024:
            part = conn.recv(1024)
            if not part:
                break
            req += part
            if b"\n" in req:
                break

        command = req.decode(errors="ignore").strip()
        print(f"Request: {command}")
        if not command.startswith("GET "):
            conn.sendall(b"ERR Unknown command\n")
            return

        filename = command.split(" ", 1)[1].strip()
        if not filename:
            conn.sendall(b"ERR No filename\n")
            return

        src_path = Path(filename)
        if not src_path.exists() or not src_path.is_file():
            err = f"ERR File not found: {filename}\n".encode()
            conn.sendall(err)
            return

        # Create temporary gzip file on disk (same dir as server's tmp) to avoid large memory usage
        with tempfile.NamedTemporaryFile(prefix="send_", suffix=".gz", delete=False) as tmp:
            gz_path = tmp.name

        try:
            print(f"Compressing {src_path} -> {gz_path} ...")
            compress_file_to_gzip(str(src_path), gz_path)
            print("Compression finished, starting chunked send.")
            ok = send_file_in_chunks(conn, gz_path)
            if ok:
                conn.sendall(b"DONE")
                print("Transfer complete; sent DONE.")
            else:
                conn.sendall(b"ERR Transfer failed")
        finally:
            # remove temp gz file
            try:
                if os.path.exists(gz_path):
                    os.remove(gz_path)
                    print(f"Removed temporary file {gz_path}")
            except Exception as e:
                print(f"Failed to remove temp gz file: {e}")

    except Exception as e:
        print(f"Exception while handling client {addr}: {e}")
    finally:
        try:
            conn.close()
        except:
            pass
        print(f"Connection closed: {addr}")

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    print(f"Compressed-FTP Server listening on {SERVER_HOST}:{SERVER_PORT}")

    try:
        while True:
            conn, addr = server_socket.accept()
            # For simplicity this example handles one client at a time synchronously.
            # For production, spawn a thread/process or use asyncio.
            handle_client(conn, addr)
    except KeyboardInterrupt:
        print("Shutting down.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()
