# Multi-Client TCP File Transfer Server (C, Linux)

A file-transfer server and client written in C using POSIX sockets. Several
clients can upload files at the same time (one `pthread` per connection), and
every transfer is verified end to end with a **SHA-256 implemented from scratch**.

## Features
- TCP server/client using `socket`, `bind`, `listen`, `accept`, `connect`
- Custom binary protocol with a fixed header (see below)
- Correct handling of partial `send()`/`recv()` calls (`read_full` / `write_full`)
- One detached `pthread` per client; a mutex protects the shared log and counters
- SHA-256 from the FIPS 180-4 spec, validated against NIST test vectors
- Files are written to a temporary `.part` file and renamed only after the hash matches
- Rejects path-traversal file names (`../x`, `a/b`) and files over 1 GiB

## Build and run
```bash
make                           # builds server, client, test_sha256

./server 5000 uploads          # terminal 1
./client 127.0.0.1 5000 myfile.pdf   # terminal 2
```
The client exits with code 0 only if the server confirms the hash matched.

## Tests
```bash
make test
```
- `test_sha256` checks the hash against NIST vectors (empty string, "abc",
  the 448-bit message, one million `a`, and streaming in uneven chunks).
- `test.sh` starts the server, uploads empty, 1-byte, odd-sized, 5 MB and 20 MB
  files **in parallel**, and compares each stored file to the original with `cmp`.
  It also checks that a path-traversal name and a corrupted hash are both rejected.

## Protocol
All integers are big-endian.

```
client -> server:  name_len (2) | file_size (8) | file name | file bytes | SHA-256 (32)
server -> client:  status (1)   0 = OK, 1 = hash mismatch, 2 = bad request, 3 = I/O error
```

## Files
| File | Purpose |
|---|---|
| `server.c` | Accepts connections, spawns a thread per client, receives and verifies files |
| `client.c` | Sends a file and its SHA-256, reports the server's verdict |
| `sha256.c/.h` | Streaming SHA-256 (`init` / `update` / `final`) |
| `net_util.c/.h` | `read_full` / `write_full` loops for partial reads and writes |
| `protocol.h` | Wire-format constants and status codes |
| `test_sha256.c`, `test.sh` | Unit and end-to-end tests |

## Known limitations
- Two clients uploading the same file name at the same time: the last one to finish wins.
- One thread per client (a thread pool would scale better).
- No encryption or authentication: SHA-256 detects corruption, not tampering by an attacker.
