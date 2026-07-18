#!/usr/bin/env bash
# =============================================================================
# build_rootfs_live555.sh
# ────────────────────────────
# live555 RTSP server @ ceeb4f4 (ASAN-instrumented, single-process).
# Binary: testProgs/testOnDemandRTSPServer, port 8554.
#
# Two CVEs are present at ceeb4f4; only ONE is reachable by the RTSP fuzzer:
#   • CVE-2020-24027 (REACHABLE — the fuzz target): stack BOF in
#     RTSPServer::RTSPClientSession::handleCmd_PLAY(). A PLAY request whose
#     `Range: clock=<long>` start value exceeds ~90 chars overflows
#     `char buf[100]` via `sprintf(buf, "Range: clock=%s-%s\r\n", absStart,
#     absEnd)` (absStart/absEnd come from parseRangeHeader of the request's
#     `Range: clock=` value). Pure-RTSP path → the fuzzer (which sends PLAY)
#     reaches it; ASAN abort_on_error → PID1 death → VM exit → detected.
#   • CVE-2018-4013 (also present but UNREACHABLE by this fuzzer): stack BOF
#     in handleHTTPCmd_TunnelingPOST (RTSP-over-HTTP tunneling, port 80, HTTP
#     POST). The fuzzer speaks pure RTSP on 8554, so this path is never hit.
#     Kept for reference only — do NOT report it as a fuzz-found bug.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FC_ENV="${PROJECT_ROOT}/sandbox/firecracker_env"
OUTPUT="${FC_ENV}/rootfs_live555.ext4"
ROOTFS_SIZE_MB=256
DOCKERFILE="${FC_ENV}/Dockerfile.live555"

echo "============================================================"
echo "  Building live555 @ ceeb4f4 RootFS"
echo "  Reachable fuzz target: CVE-2020-24027 (PLAY Range: clock= BOF)"
echo "  (CVE-2018-4013 also present but unreachable by the RTSP fuzzer)"
echo "============================================================"
mkdir -p "${FC_ENV}"

cat > "${DOCKERFILE}" << 'DEOF'
# live555 @ ceeb4f4 = CVE-2018-4013 (stack BOF in RTSP-over-HTTP tunneling).
# handleHTTPCmd_TunnelingPOST copies Base64-decoded RTSP data into a fixed
# stack buffer via changeClientInputSocket → handleRequestBytes → overflow.
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ make git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN cd /tmp && \
    git clone https://github.com/rgaufman/live555.git && \
    cd live555 && git checkout ceeb4f4 && \
    ./genMakefiles linux && \
    make -j"$(nproc)" CFLAGS="-fsanitize=address -static-libasan -g -O1 -fno-stack-protector" \
         CXXFLAGS="-fsanitize=address -static-libasan -g -O1 -fno-stack-protector" \
         LDFLAGS="-fsanitize=address -static-libasan" && \
    cp testProgs/testOnDemandRTSPServer /usr/local/bin/ && \
    chmod +x /usr/local/bin/testOnDemandRTSPServer

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/testOnDemandRTSPServer /usr/local/bin/testOnDemandRTSPServer

# /init: PID 1 — boots RTSP server on 0.0.0.0:8554.
RUN printf '#!/bin/sh\n\
mount -t proc proc /proc\n\
mount -t sysfs sysfs /sys\n\
mount -t devtmpfs devtmpfs /dev\n\
mkdir -p /dev/pts\n\
mount -t devpts devpts /dev/pts\n\
ip link set lo up\n\
ip addr add 172.16.0.2/24 dev eth0\n\
ip link set eth0 up\n\
ip route add default via 172.16.0.1\n\
export ASAN_OPTIONS=disable_coredump=1:abort_on_error=1:halt_on_error=1:detect_leaks=0\n\
exec /usr/local/bin/testOnDemandRTSPServer 8554\n' > /init && chmod +x /init
DEOF

echo "Building Docker image..."
docker build -t lifa-live555 -f "${DOCKERFILE}" "${FC_ENV}" 2>&1 | tail -20

echo "Exporting to ext4 (${ROOTFS_SIZE_MB}MB)..."
WORK_DIR=$(mktemp -d)
docker run --rm --privileged \
  -v "${FC_ENV}:/output" \
  -v "${WORK_DIR}:/work" \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  lifa-live555:latest \
  bash -c "
set -e
cd /
tar cf /work/rootfs.tar --exclude=./proc --exclude=./sys --exclude=./dev/pts --exclude=./output --exclude=./work .
dd if=/dev/zero of=/output/rootfs_live555.ext4 bs=1M count=${ROOTFS_SIZE_MB} status=none
mkfs.ext4 -F -q /output/rootfs_live555.ext4
mkdir -p /mnt/rootfs
mount -o loop /output/rootfs_live555.ext4 /mnt/rootfs
tar xf /work/rootfs.tar -C /mnt/rootfs
sync
umount /mnt/rootfs
chown \"\${HOST_UID}:\${HOST_GID}\" /output/rootfs_live555.ext4
"
rm -rf "${WORK_DIR}" "${DOCKERFILE}"
echo ""
echo "✓ live555 RootFS: ${OUTPUT} ($(du -h "${OUTPUT}" | cut -f1))"
echo "  CVE-2018-4013: stack BOF in RTSP-over-HTTP tunneling (no auth needed)"
echo "============================================================"
