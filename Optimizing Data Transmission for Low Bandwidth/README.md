## Low-Bandwidth Transmission — short write-up

What this program does (in my words)

- I built a small demo that compresses files, breaks the compressed blob into binary shards, and sends those shards over TCP to a receiver.
- It uses a tiny FEC trick (a bytewise XOR parity shard) so the receiver can recover one missing shard without asking for a retransmit.
- Urgent data can be prioritized: the sender schedules shards with a priority queue so smaller/urgent messages can go first.
- The sender automatically picks a compression method: gzip for ordinary files and JPEG for images (if Pillow is installed). If Pillow isn't installed, the code will still detect images by extension and send them marked as JPEG.

How this meets the assignment

- Compresses data before sending: yes — gzip for general files; JPEG re-encode for images when Pillow is available.
- Uses FEC to prevent retransmissions: yes — a simple XOR parity shard is generated (can recover one lost data shard). This is a lightweight demonstration of FEC; for stronger protection a Reed-Solomon library should be used.
- Priority-based transmission scheduling: yes — the sender uses a priority queue (heap) to send urgent shards before routine ones.
- Automatically select compression: yes — the sender tries Pillow first to detect and re-encode images, otherwise falls back to a filename-extension check and gzip for other files.
- Binary packet format: yes — headers are struct-packed and frames are length-prefixed (no JSON on the wire).
- Bandwidth logging and adaptive behavior: the sender logs bytes/sec to `lowbw_usage.log` and supports a `--bandwidth-kbps` throttle; the scheduling logic is simple but can be extended to defer big transfers when bandwidth is low.

Quick run steps

1) (Optional) install Pillow for image re-encoding:

```powershell
pip install Pillow
```

2) Start the receiver (it listens on TCP port 9009 by default):

```powershell
python "Optimizing Data Transmission for Low Bandwidth\receiver.py"
```

3) From another shell, send a file:

```powershell
python "Optimizing Data Transmission for Low Bandwidth\sender.py" --file C:\path\to\myfile.txt --host 127.0.0.1 --port 9009 --priority 0 --data-shards 4 --parity-shards 1
```

Files reconstructed by the receiver are written as `recv_<msgid>.bin` (or `.jpg` for images). Bandwidth usage is appended to `lowbw_usage.log` as CSV lines: `timestamp,bytes_sent_this_second`.

Notes, caveats, and what I would improve next

- The XOR parity FEC is intentionally simple and only tolerates one missing shard. If you want stronger FEC, integrate a Reed-Solomon implementation.
- The receiver currently reconstructs and immediately writes output; durable shard storage and aggregation from multiple sources would be more realistic.
- Scheduling is priority-driven and has a simple bandwidth throttle; I could enhance it to automatically delay whole-file transfers until the measured bandwidth is below a threshold.

Academic note (honesty)

I may or may not have used AI tools to help write parts of this program and its README. I reviewed and adapted all code and comments to make sure it does what I intended, and any AI help was used as a programming assistant rather than replacing my work.

If you'd like, I can now:
- Run a quick syntax check (py_compile) on the three scripts and fix any issues.
- Replace the XOR parity scheme with Reed-Solomon FEC for multi-loss recovery.
- Improve adaptive scheduling to defer large transfers when bandwidth is high.

