#!/usr/bin/env bash
# =============================================================================
# build_rootfs_lightftp.sh
# ────────────────────────────
# Production build script for LightFTP Firecracker rootfs.
#
# Strategy: All-in-one Docker build (no SSH, no runtime provisioning).
# LightFTP is compiled WITH AddressSanitizer (static-linked) inside Docker,
# then a minimal runtime image is exported to ext4.
#
# Output: sandbox/firecracker_env/rootfs_lightftp.ext4 (~100MB)
#
# Usage:
#   bash scripts/build_rootfs_lightftp.sh
#
# Prerequisites:
#   Docker (used for rootfs assembly — no host mount/sudo needed)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FC_ENV="${PROJECT_ROOT}/sandbox/firecracker_env"
OUTPUT="${FC_ENV}/rootfs_lightftp.ext4"
ROOTFS_SIZE_MB=256
DOCKERFILE="${FC_ENV}/Dockerfile.lightftp-rootfs"

echo "============================================================"
echo "  Building LightFTP Firecracker RootFS (All-in-One)"
echo "============================================================"

# ── Create multi-stage Dockerfile ──────────────────────────────────────────

mkdir -p "${FC_ENV}"

cat > "${DOCKERFILE}" << 'DEOF'
# Stage 1: Build LightFTP with ASAN
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc make git libssl-dev libc6-dev libgnutls28-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN cd /tmp && \
    git clone https://github.com/hfiref0x/LightFTP.git && \
    cd LightFTP && git checkout 5980ea1 && \
    cd Source/Release && \
    gcc -fsanitize=address -static-libasan -g -O2 -c ../*.c -I.. && \
    gcc -fsanitize=address -static-libasan -g -O2 -o fftp *.o -lpthread -lgnutls && \
    cp fftp /usr/local/bin/fftp && chmod +x /usr/local/bin/fftp

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 libssl3 libgnutls30 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/fftp /usr/local/bin/fftp

RUN mkdir -p /tmp/ftp_root && \
    printf '[ftpconfig]\nport=21\ninterface=0.0.0.0\nexternal_ip=172.16.0.2\nlocal_mask=255.255.255.0\nminport=1024\nmaxport=65535\nmaxusers=100\nmaxcmds=999999\n\n[admin]\npswd=*\naccs=admin\nroot=/tmp/ftp_root\n' > /etc/fftp.conf

RUN printf '#!/bin/sh\n\
mount -t proc proc /proc\n\
mount -t sysfs sysfs /sys\n\
mount -t devtmpfs devtmpfs /dev\n\
mount -t tmpfs tmpfs /tmp\n\
mkdir -p /dev/pts\n\
mount -t devpts devpts /dev/pts\n\
ip link set lo up\n\
ip addr add 172.16.0.2/24 dev eth0\n\
ip link set eth0 up\n\
ip route add default via 172.16.0.1\n\
echo "LIFA-Fuzz: LightFTP ready on 172.16.0.2:21 (ASAN enabled)"\n\
export ASAN_OPTIONS=disable_coredump=1:abort_on_error=1:halt_on_error=0\n\
exec /usr/local/bin/fftp /etc/fftp.conf\n' > /init && chmod +x /init
DEOF

# ── Build Docker image ─────────────────────────────────────────────────────

echo ""
echo "Building Docker image..."
docker build -t lifa-lightftp-complete -f "${DOCKERFILE}" "${FC_ENV}" > /dev/null

# ── Export to ext4 via Docker privileged container ──────────────────────────

echo "Exporting to ext4 (${ROOTFS_SIZE_MB}MB)..."

WORK_DIR=$(mktemp -d)

docker run --rm --privileged \
  -v "${FC_ENV}:/output" \
  -v "${WORK_DIR}:/work" \
  lifa-lightftp-complete:latest \
  bash -c "
set -e
cd /
tar cf /work/rootfs.tar --exclude=./proc --exclude=./sys --exclude=./dev/pts --exclude=./output --exclude=./work .
dd if=/dev/zero of=/output/rootfs_lightftp.ext4 bs=1M count=${ROOTFS_SIZE_MB} status=none
mkfs.ext4 -F -q /output/rootfs_lightftp.ext4
mkdir -p /mnt/rootfs
mount -o loop /output/rootfs_lightftp.ext4 /mnt/rootfs
tar xf /work/rootfs.tar -C /mnt/rootfs
umount /mnt/rootfs
rm -f /work/rootfs.tar
"

rm -rf "${WORK_DIR}" "${DOCKERFILE}"

echo ""
echo "✓ LightFTP RootFS: ${OUTPUT}"
echo "  Size: $(du -h "${OUTPUT}" | cut -f1)"
echo ""
echo "  LightFTP: ASAN-enabled, static-linked, bound to 0.0.0.0:21"
echo "  Boot: init=/init → fftp directly (no SSH)"
echo ""
echo "  Launch:"
echo "    python3 main.py --driver firecracker"
echo ""
echo "============================================================"
