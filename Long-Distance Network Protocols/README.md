# Long-Distance Messaging (DTN-style) — notes

What I built

- A small DTN-style store-and-forward relay (`relaynode.py`) that accepts encrypted, sharded message shards and stores them until a receiver fetches them. The relay can forward shards to neighbor relays to simulate multi-hop routing.
- A sharded sender (`sendernode.py`) that splits a message into data shards, computes a simple XOR parity shard (1 parity) as FEC, encrypts each shard using AES-GCM, and sends shards to a relay.
- A fetcher/receiver (`receivernode.py`) that asks a relay for messages targeted at a destination, receives encrypted shards, decrypts them, reconstructs the message using the parity shard if one data shard is missing, and writes the result to disk.

How this matches the assignment

- DTN store-and-forward: relays store incoming shards in memory (grouped by message ID) and only release them when a fetch request arrives. Relays optionally forward shards to configured neighbor relays to simulate multiple hops.
- FEC instead of retransmission: the sender creates an XOR parity shard that allows recovery of one missing data shard without retransmitting. This demonstrates FEC basics; for multi-loss environments you'd replace the XOR parity with Reed-Solomon.
- Adaptive scheduling: relays include a simple bandwidth window (bytes sent per second) and will defer forwarding of non-urgent shards if the per-second budget is exceeded. The sender can provide a `--priority` flag (0=urgent). This is a basic adaptive scheduler you can extend.
- Priority messages: shards carry a `priority` value and relays send stored shards to fetchers ordered by priority (lower value first).
- Encryption: shards are encrypted with AES-GCM derived from a passphrase (PBKDF2). This ensures confidentiality and integrity of shard payloads.

How to run (quick)

1) Start the first relay (default port 9000):

```powershell
python "Long-Distance Network Protocols\relaynode.py" --port 9000 --pass demo --neighbor 127.0.0.1:9001
```

2) Start a second relay (to simulate multi-hop):

```powershell
python "Long-Distance Network Protocols\relaynode.py" --port 9001 --pass demo
```

3) Send a file from the sender (sharded, encrypted):

```powershell
python "Long-Distance Network Protocols\sendernode.py" --relay-host 127.0.0.1 --relay-port 9000 --dest "Earth Control" --file C:\path\to\file.bin --pass demo --data-shards 4 --parity-shards 1 --priority 1
```

4) Fetch messages at the receiver (asks relay for `--dest`):

```powershell
python "Long-Distance Network Protocols\receivernode.py" --relay-host 127.0.0.1 --relay-port 9001 --dest "Earth Control" --pass demo
```

Notes, caveats, and next steps

- The current FEC is XOR parity (recovers only one missing data shard). For robust multi-loss tolerance replace with Reed-Solomon (e.g., `reedsolo`).
- Shards are stored in-memory at relays. For realistic DTN you'd add persistent storage and time-to-live handling.
- Key management is simplified: all nodes derive AES keys from the same passphrase. In production you'd use secure key exchange or per-node keys.
- The relay forwarding tries to respect a per-second bandwidth budget and defers non-urgent traffic when the budget is exceeded; this demonstrates adaptive scheduling but can be improved.


