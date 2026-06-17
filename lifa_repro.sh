#!/usr/bin/env bash
# =============================================================================
# LIFA-Fuzz crash reproduction script (POSITIVE-CONTROL proof)
# =============================================================================
# Reproduces the LIFA v2 PROCESS_DATA stack-buffer-overflow discovered by the
# fuzzer, on a FRESH build of the target — no fuzzer, no LLM, no magic.
#
# It rebuilds sandbox/target/vulnerable_server.c from source (ASAN), starts it
# on a local port, then replays the exact PoC packet saved by the fuzzer:
#     [new conn] → PING (INIT→AUTH) → PROCESS_DATA(payload=4327B > 64B buffer)
# and asserts the server crashes with an AddressSanitizer report.
#
# Usage:  bash lifa_repro.sh [path/to/poc.bin]
# =============================================================================
set -euo pipefail

PROJ="/home/trieudai/LIFA-Fuzz"
POC="${1:-/tmp/lifa_poc.bin}"
PORT="${2:-9099}"

echo "=== 1. Rebuild target from source (ASAN, no fuzzer) ==="
gcc -O0 -fno-stack-protector -z execstack -no-pie -static-libasan -fsanitize=address -g \
    -o /tmp/lifa_repro_server "$PROJ/sandbox/target/vulnerable_server.c"
echo "  built /tmp/lifa_repro_server"

echo "=== 2. Start fresh target on port $PORT ==="
/tmp/lifa_repro_server "$PORT" > /tmp/lifa_repro.log 2>&1 &
SRV=$!
sleep 0.6
echo "  pid=$SRV"

echo "=== 3. Replay PoC: PING (auth) → PROCESS(overflow) ==="
python3 - "$POC" "$PORT" << 'PY'
import socket, struct, sys
poc = open(sys.argv[1], 'rb').read()
port = int(sys.argv[2])
MAGIC = b"LIFA"
def pkt(op, pl=b""): return MAGIC + bytes([0x01, op]) + struct.pack("<H", len(pl)) + pl
s = socket.socket(); s.settimeout(4); s.connect(("127.0.0.1", port))
s.sendall(pkt(0x01, b"auth"))           # PING: INIT → AUTHENTICATED
pong = s.recv(64)
print(f"  PING → response opcode 0x{pong[5]:02x} (0x81=PONG, auth OK)")
s.sendall(poc)                          # PROCESS_DATA: payload > 64B buffer
print(f"  sent PROCESS: opcode=0x{poc[5]:02x} declared_len={struct.unpack('<H',poc[6:8])[0]} actual={len(poc)-8}")
try:
    s.recv(64); print("  [unexpected] server responded (no crash)")
except (ConnectionResetError, BrokenPipeError):
    print("  connection reset / pipe broken → child CRASHED (expected)")
s.close()
PY

echo "=== 4. Wait for parent exit (CRASH_THRESHOLD=1) ==="
for i in $(seq 1 20); do kill -0 $SRV 2>/dev/null || break; sleep 0.2; done
wait $SRV 2>/dev/null && RC=0 || RC=$?

echo ""
echo "=== 5. Result ==="
if grep -q "AddressSanitizer" /tmp/lifa_repro.log; then
    echo "  ✓ REPRODUCED — ASAN caught a real memory error"
    grep -iE "AddressSanitizer|memcpy-param|overflow|SUMMARY" /tmp/lifa_repro.log | head -3
    echo "  parent exit code: $RC"
else
    echo "  ✗ NOT reproduced (no ASAN report)"
    tail -5 /tmp/lifa_repro.log
    exit 1
fi
