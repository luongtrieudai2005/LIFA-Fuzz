# Vulnerable TCP Server for E2E Testing

A deliberately vulnerable stateful TCP server used for LIFA-Fuzz end-to-end integration tests.

## Protocol

```
Client                          Server
  │                               │
  │──── "HELLO\n" ──────────────▶│  (handshake)
  │◀─── "OK\n" ─────────────────│
  │                               │
  │──── payload ───────────────▶│  (fuzz target)
  │                               │
  │◀─── "BYE\n" ────────────────│  (normal response)
  │                               │
```

## Crash Triggers

The server will **crash with SIGSEGV** (exit code 139) if either:

1.  The payload contains the string `"CRASH_ME"`
2.  The payload length exceeds **1024 bytes**

Both triggers cause a null-pointer dereference: `int *p = NULL; *p = 0xDEAD;`

## Build & Run

```bash
make
./vulnerable_server 9999
```

## Test Manually

```bash
# Normal interaction (no crash)
echo -ne "HELLO\nNormal payload\n" | nc 127.0.0.1 9999

# Trigger crash with string
echo -ne "HELLO\nCRASH_ME\n" | nc 127.0.0.1 9999

# Trigger crash with oversized payload
python3 -c "
import socket
s = socket.socket()
s.connect(('127.0.0.1', 9999))
s.send(b'HELLO\n')
print(s.recv(64))
s.send(b'A' * 1025)
print(s.recv(64))
"
```

## Architecture

- **Fork-based**: Each connection is handled in a child process.
- **Crash isolation**: When a child crashes (SIGSEGV), the parent process
  survives and accepts new connections.
- **SIGTERM handler**: Clean shutdown on `kill` command.
- **SIGCHLD ignored**: Auto-reap crashed children.

## Exit Codes

| Code | Meaning |
|------|---------|
| 139  | SIGSEGV — crash triggered by fuzzing payload |
| 0    | Clean shutdown (SIGTERM received) |
| 1    | Startup error (bind/listen failure) |
