
# MarsMail — my store-and-forward messaging toy

This is my MarsMail project — a small store-and-forward demo I put together so I can send encrypted messages (and attachments) through a relay.

Quick rundown of what it does:

- Encrypts and stores messages on a relay.
- Supports attachments (images, logs, whatever) embedded in the message.
- Compresses the payload before encryption (gzip) so transmissions use less bandwidth.
- Uses hybrid encryption: AES-GCM for the payload (confidentiality + integrity) and RSA to encrypt the AES key.
- Logs successes and failures to `marsmail.log`.

Files you should care about

- `generate_keys.py` — run this once to create `receiver_public_key.pem` and `receiver_private_key.pem`.
- `sender.py` — builds the message (subject, body, attachments), compresses and encrypts it, then sends it to the relay.
- `relay.py` — the store-and-forward node (listens on `127.0.0.1:9300`, stores per-recipient, and forwards on fetch).
- `receiver.py` — asks the relay for messages addressed to a recipient, decrypts and decompresses them, prints the body, and saves attachments under `attachments_received/`.
- `requirements.txt` — python deps: `rsa` and `cryptography`.

How I run it (PowerShell)

Open PowerShell in the `Build and Test a MarsMail System` folder and run:

```powershell
python -m pip install -r requirements.txt
python generate_keys.py        # do this once
python relay.py                # keep this running in its own terminal
python sender.py               # example message is sent by the script
python receiver.py             # fetches and prints messages for the example recipient
```

If I want to send attachments I call `send_email(..., attachments=['C:\path\to\file'])` from a script or change the example in `sender.py`.

What actually happens

1. `sender.py` creates a JSON payload with `subject`, `body`, and an `attachments` list (filename + base64 data).
2. The payload is gzipped (compression happens before encryption).
3. I generate a random AES-256 key and encrypt the compressed payload with AES-GCM.
4. The AES key is encrypted with the receiver's RSA public key and sent along with the ciphertext.
5. The relay stores messages under the recipient ID. When the receiver fetches, the relay returns those messages.
6. `receiver.py` decrypts the AES key with the receiver's private RSA key, decrypts with AES-GCM, decompresses, and saves attachments.

Where files and logs go

- Attachments received are written to `attachments_received/`.
- Runtime log output (success/failure) goes to `marsmail.log` in the same folder.

Quick troubleshooting and notes

- If a dependency is missing: `python -m pip install -r requirements.txt`.
- If decryption fails: make sure `receiver_private_key.pem` is present and matches the public key used by the sender.
- I avoided `pickle` for transport and used length-prefixed JSON frames — that makes the wire format safer and simpler to debug.
- This demo does not authenticate senders (the `sender` field is just a string). If I want strong sender identity I should add signatures.

