
# DFSS (Distributed File Storage System) — my quick demo

I put together a tiny DFSS demo to play with chunked uploads/downloads between simple peers.

What you'll find here

- `dfss_peer.py` — a minimal peer that holds chunks in memory and answers three requests: `store_chunk`, `get_chunk`, and `get_file_info`.
- `dfss_uploader.py` — splits a file into fixed-size chunks, computes a SHA-256 checksum for each chunk, and uploads them round-robin to the peers you list.
- `dfss_downloader.py` — asks a peer how many chunks a file has, then downloads the chunks in parallel (with retry/backoff), checks checksums and reassembles the file.

Protocol notes (short)

- Messages are framed with a 4-byte big-endian length prefix and use `pickle` for the demo's simplicity.
- Supported operations: `store_chunk`, `get_chunk`, `get_file_info`.
- Every chunk carries a SHA-256 checksum. Peers validate the checksum when storing; the downloader validates again when receiving.

How I run this locally

1) Start at least two peers (each in its own shell). The script defaults to port 9000; run a second instance on another machine or change the port in the script for a second instance.

```powershell
python .\DFSS\dfss_peer.py
# in another shell change the port in the script or run on a different host/VM
```

2) Upload a file to the cluster. The uploader takes a comma-separated list of peers (host:port) and will spread chunks across them.

```powershell
python .\DFSS\dfss_uploader.py C:\path\to\file.txt 127.0.0.1:9000,127.0.0.1:9001
```

3) Download and reassemble the file (downloader asks peers for the total chunk count first):

```powershell
python .\DFSS\dfss_downloader.py file.txt 127.0.0.1:9000,127.0.0.1:9001
```

Notes (for me / next steps)

- This is intentionally simple: storage is in-memory so restarting a peer loses its chunks.
- If I want to make this more robust I should: replace `pickle` with a safe format (protobuf/msgpack/JSON), add persistent chunk storage (files or a small DB), and add authentication/encryption for peer communication.

