# File Transfer Pipeline

A TCP file transfer tool for Windows, written in C++.

I wasn't comfortable leaving the security of my data to the companies whose apps I use,
so I decided to write my own transfer protocol. I started with the foundation: files go
directly between two computers, with no third-party server in between.

I had three goals for this project:
- See how data transfer works at a low level
- Learn C++, a language I had never used before
- Experience how an attacker thinks, and how to build defenses against it

For two weeks I looked at my own code from an attacker's point of view and fixed every
weakness I found. Throughout the process I used AI as a tutor and code reviewer.

Traffic is not encrypted yet. The next step is adding end-to-end encryption using a
well-tested library.

## Features

- Streams files in 64 KB chunks, so large files are never loaded into memory
- Handles partial `send()` / `recv()` calls correctly (`send_all` / `recv_all` loops)
- SHA-256 integrity check, sent as a trailer after the file data
- Deletes partial or corrupted files (hash mismatch, connection loss, disk write error)
- Whitelist-based file name validation (path traversal, ADS, null byte, control characters)
- Header length and size limits checked **before** any memory is allocated
- Robustness test suite with 17 attack and edge-case scenarios

## Protocol

```
| Header (12 B) | File name (N B) | File data (file_size B) | SHA-256 (32 B) |
```

| Field           | Type     | Size | Notes                                  |
|-----------------|----------|------|----------------------------------------|
| `file_size`     | uint64   | 8 B  | Size of the file data in bytes         |
| `file_name_len` | uint32   | 4 B  | Length of the file name (1-255)        |
| File name       | bytes    | N B  | Not null-terminated                    |
| File data       | bytes    | ...  | Sent in 64 KB chunks                   |
| SHA-256         | bytes    | 32 B | Hash of the file data                  |

The header is packed (`#pragma pack(1)`) and its size is enforced with `static_assert`.

### Why a trailer? 
I put the hash at the end (as a trailer) instead of the header for two reasons.
First, efficiency: the hash is only known after the whole file has been read. With the
hash in the header, the sender would have to read the file from disk twice, once to
compute the hash and once to send it. With a trailer, the file is read once and hashed
while it is being sent. Second, consistency: the file could change between the two
reads, and the data sent would no longer match the hash.

## Build

Tested with MinGW-w64 (g++) on Windows:

```
g++ -std=c++17 main.cpp -o main.exe -lws2_32 -lbcrypt
```

## Usage

```
main.exe server <port>
main.exe client <ip> <port> <file_path>
```

Example:

```
> main.exe server 8080
[*] Port 8080 listening, Connecting...
[+] Incoming file: video.mp4 (25525033 bytes)
[+] The file was received and verified: received_video.mp4
[+] SHA-256: 5fb99b60d81aa4b5005666c86835cceb1be11d63824fc4ebb16e2c315cec50f4

> main.exe client 127.0.0.1 8080 video.mp4
[+] 3-Way Handshake has completed, pipeline is active.
[+] The file was sent successfully: video.mp4 (25525033 bytes)
[+] SHA-256: 5fb99b60d81aa4b5005666c86835cceb1be11d63824fc4ebb16e2c315cec50f4
```

## Security

### Trust boundary

The trust boundary is `recv()`. The receiver assumes the sender may be an attacker running
their own client, so no field coming from the network is trusted: lengths are bounded,
the file name is validated, and the content is verified against the hash.

### Threats and mitigations

| Threat | Mitigation |
|---|---|
| Path traversal (`../`, `..\`) | Everything up to the last `/` or `\` is stripped |
| NTFS Alternate Data Streams (`file.txt:hidden`) | `:` is rejected |
| Null byte injection (`evil.exe\0.txt`) | Null bytes are rejected |
| Log injection (newline or escape codes in the name) | Control characters are rejected; the name is logged only after validation, and rejected bytes are logged as hex |
| Hidden files, `.` and `..` | Names starting with `.` are rejected |
| Windows name normalization (`file.txt.`, `file.txt `) | Names ending with `.` or a space are rejected |
| Unexpected characters | Whitelist: ASCII letters, digits and ` . - _ ( ) + @ , [ ]` only |
| Oversized name length (memory exhaustion) | `file_name_len` must be 1-255, checked before allocation |
| Oversized file (disk exhaustion) | `file_size` is limited to 10 GiB |
| Malformed input crashing the server | Validation errors are caught; the connection is rejected, the server does not crash |
| Corrupted or truncated transfer | SHA-256 is verified; on mismatch or connection loss the file is deleted |

### What this does **not** protect against

- **Integrity, not authentication.** SHA-256 detects accidental corruption and truncation.
  An attacker who can modify the traffic can also replace the hash. Protecting against that
  would require an HMAC or a digital signature.
- **No encryption.** Traffic is sent in plaintext; anyone on the network path can read the file.

## Testing

### Automated robustness tests

```
python tests\test_transfer.py
```


The tests answer one question: if an attacker abuses the transfer channel while sending a
file, how well does the receiver hold up? Covered scenarios include path traversal, ADS,
null bytes, log injection, length limits, a wrong hash and a connection dropped mid-transfer.

Each test starts a fresh server in an empty temporary directory, builds the wire format
by hand like a malicious client would, and checks both what the server logged and which
files were left on disk.

```
17/17 passed
```


While writing these tests I saw how easily a receiver with no defenses would let an
attacker write a file anywhere, hide it, or forge log lines. Here, all of these attempts
are rejected. Note that the tool does not inspect file contents, so it will not detect a
malicious file. It only prevents the attacker from controlling where and how that file
is written.

On its first run, the suite caught a real bug: `+` was missing from the allowed characters,
so a legitimate file name was rejected. Fixed in v0.5.2.

### Manual tests

- **Integrity:** a 25 MB file produced the same SHA-256 on the sender, the receiver and
  Windows `certutil -hashfile`.
- **Corruption:** I flipped one bit per chunk after hashing. The receiver detected the
  mismatch, logged both hashes and deleted the file. This covers accidental corruption and
  truncated transfers, not an attacker who can also replace the hash (see Security).

## Known Limitations

- Single connection: the server handles one transfer and exits
- No encryption or authentication (see Security)
- No socket timeouts: a client that connects and stays silent blocks the server
- An existing `received_<name>` file is overwritten
- Non-ASCII file names are rejected (UTF-8 to UTF-16 conversion not implemented)
- Header is sent in host byte order (little-endian on x86), not portable across architectures
- Windows only

## Roadmap
- End-to-end encryption using an existing library (TLS or libsodium), not custom crypto
- Socket timeouts
- Concurrent connections (`accept` loop)
- Overwrite protection
- Explicit big-endian wire format with magic bytes and a protocol version
- Detection side: capture this tool's traffic and write Suricata / Zeek / Sigma rules for it

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE).
