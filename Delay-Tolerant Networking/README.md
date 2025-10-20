
# DTN notes (short personal log)

This folder has three small scripts I wrote quickly for the assignment. I kept the code small so I could hand it in, but put enough comments so I can remember what I did later.

- `DTN-RELAYnode.py` — relay server (stores and forwards messages).
- `DTN-SENDER.py` — sends an encrypted message to the relay.
- `DTN-Receiver.py` — asks the relay for stored messages and prints them.

If you come back to this later, here are the key points so you don't have to re-figure everything out.

## How it basically works

- Messages are framed: 4-byte big-endian length + `pickle` bytes.
- Sender flow:
   1. make plaintext payload (bytes)
   2. compute SHA-256 checksum of plaintext
   3. encrypt plaintext with AES-GCM (iv + tag + ciphertext)
   4. send a dict {status:'store', from, destination, urgent, payload:encrypted, checksum}
- Relay flow:
   - accepts many clients (thread per connection)
   - on `store`: decrypt/check checksum and put the message in memory under `destination` (urgent queue first)
   - on `fetch`: send urgent messages first, then normal ones, then send `{status:'done'}`
- Receiver flow:
   - send `{status:'fetch', destination: <id>}`
   - receive framed messages, decrypt payload, check checksum, print contents

## Useful quick commands (Windows PowerShell)

Start relay (terminal 1):

& "C:/Program Files/Python313/python.exe" "DTN-RELAYnode.py"

Send example message (terminal 2):

& "C:/Program Files/Python313/python.exe" "DTN-SENDER.py"

Fetch messages (terminal 3):

& "C:/Program Files/Python313/python.exe" "DTN-Receiver.py"

If something breaks, check that `pycryptodome` is installed and that you're running the scripts from this folder.

## Quick TODO / improvements I intended to add later

- persist messages to disk so they survive a restart
- replace `pickle` with protobuf (or JSON) for interoperability
- better key management (don't hard-code secrets)
- retry/backoff logic for forwarding

That's it for now — this is written for future-me so I can open it later and remember the overall design quickly.
