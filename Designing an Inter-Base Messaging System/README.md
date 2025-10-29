# Inter-Base Messaging System (IBMS) — quick notes

This folder contains a small IBMS demo (peer, sender, receiver). I wrote this to store-and-forward messages between bases with priority, encryption, and optional multi-hop routing. This README is a short reminder for future me explaining what's happening and how to test it.

Files
- `peer.py` — the base/peer server. Accepts framed (4-byte length) pickled messages. Supports two operations:
  - `store_message`: accepts an encrypted payload + checksum + destination + urgent flag + optional `route` (list of (host,port)). The peer decrypts to validate checksum, then stores the encrypted payload in an in-memory, per-destination priority queue (urgent first). If `route` is present the peer attempts to forward to the next hop.
  - `fetch_messages`: client requests stored messages for a destination; peer sends urgent messages first, then normal messages, then `{'status':'done'}`.

- `sender.py` — example sender. Builds a message, computes SHA-256 checksum of plaintext, encrypts payload with AES-GCM, and sends a framed `store_message` packet. Waits for peer response (stored/forwarded/nack).

- `receiver.py` — example receiver. Sends a framed `fetch_messages` request for a destination, receives messages, decrypts them, validates checksum, and prints the message body.

Security & design notes
- Encryption: AES-GCM with a demo password-derived key (PBKDF2). The peer decrypts incoming payloads to validate checksum but stores the encrypted blob (so stored data remains encrypted in memory).
- Checksum: SHA-256 of plaintext. If checksum mismatches, the peer rejects the message.
- Priority: per-destination store uses `urgent` and `normal` queues; urgent messages are delivered first.
- Multi-hop: sender may include `route` list; a peer will attempt to forward to the next hop and only store locally if forwarding fails.
- Logging: peer appends events to `ibms.log` (in the same folder).

How to run 
1) Start a peer (acts as a base) in a terminal:

```powershell
& "C:/Program Files/Python313/python.exe" "Designing an Inter-Base Messaging System/peer.py"
```

2) Send a message (in another terminal):

```powershell
& "C:/Program Files/Python313/python.exe" "Designing an Inter-Base Messaging System/sender.py"
```

3) Fetch messages (in another terminal):

```powershell
& "C:/Program Files/Python313/python.exe" "Designing an Inter-Base Messaging System/receiver.py"
```

Quick tests / things to try
- Priority test: modify `sender.py` to call `send_message(..., urgent=True)` and `send_message(..., urgent=False)`; fetch and verify urgent delivered first.
- Multi-hop test: run a second peer on a different port and pass `route=[('127.0.0.1', other_port), ('127.0.0.1', final_port)]` to `send_message` — peer will attempt forwarding.
- Checksum test: corrupt the plaintext before computing checksum in `sender.py` to force a mismatch and observe peer `nack`.

Limitations / future work
- Storage is in-memory; messages will be lost on restart. Add persistent storage for durability.
- Keys are hard-coded for the demo. Use environment variables, a keystore, or per-base keys.
- Wire format uses `pickle` for convenience. For cross-language or safer operation, move to protobuf/msgpack/JSON.

That's the minimal summary so future-me can pick this up quickly.
