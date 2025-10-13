This project is something I built to learn how data can be serialized, compressed, encrypted, and sent between a server and a client over a network.
The goal was to compare how JSON, MessagePack, and Protocol Buffers (Protobuf) perform when sending the same data — looking at things like speed and data size.

The system also adds gzip compression to shrink the data and AES-256 encryption to secure it before it gets sent.
Basically, it’s a small simulation of how real systems securely send structured data between machines.


The server acts as the sender.
Here’s what it does step by step:

It has a simple mission data dictionary — something like:

{
    "rover_id": "Perseverance",
    "battery": 85,
    "location": [45.123, -93.456],
    "status": "Exploring"
}


The server serializes that data using three different formats:

JSON (human-readable)

MessagePack (binary, smaller)

Protocol Buffers (binary, fastest and most efficient)

After serialization, it:

Compresses the data using gzip

Encrypts it using AES-256-GCM (so it’s secure)

Sends it to the client over a TCP connection

While doing that, the server logs how big each version of the data is:

The raw serialized size

The compressed size

The encrypted size

How long each step took (in milliseconds)

So, the server is like a secure data broadcaster that tries 3 ways to package and send the same message.

The client is the receiver.
Here’s what it does:

Connects to the server through TCP.

Receives each of the 3 transmissions (JSON, MessagePack, and Protobuf).

For each one, it:

Decrypts the AES-256-GCM data

Decompresses it using gzip

Deserializes it back into a Python dictionary

The client then measures:

How long each step took

The sizes of the encrypted, compressed, and raw data

The total round-trip time from receiving to decoding

At the end, it prints out a summary that compares all 3 methods — so I can see which one was the fastest and most efficient.