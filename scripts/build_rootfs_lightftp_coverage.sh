#!/usr/bin/env bash
# =============================================================================
# build_rootfs_lightftp_coverage.sh
# ─────────────────────────────────────────────────────
# COVERAGE build for the LightFTP Firecracker rootfs.
#
# Same as build_rootfs_lightftp.sh but LightFTP is compiled with gcov
# instrumentation (-fprofile-arcs -ftest-coverage) + a SIGINT/SIGTERM handler
# (gcov_flush.c) that calls __gcov_dump(), so coverage can be flushed on a
# Firecracker CtrlAltDel (→ guest SIGINT to PID 1).
#
# Coverage-data placement:
#   - GCOV_PREFIX=/opt/cov in /init  → .gcda written under
#     /opt/cov/tmp/LightFTP/Source/Release/*.gcda (persistent rootfs, NOT the
#     /tmp tmpfs which evaporates on VM stop).
#   - /opt/lightftp-build/ keeps .gcno + source (needed by host lcov).
#
# After a coverage run, the host extracts /opt/cov + /opt/lightftp-build from
# this ext4 via debugfs/loopback-mount, runs lcov --capture, parses.
#
# Output: sandbox/firecracker_env/rootfs_lightftp_coverage.ext4
#
# Usage:
#   bash scripts/build_rootfs_lightftp_coverage.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FC_ENV="${PROJECT_ROOT}/sandbox/firecracker_env"
OUTPUT="${FC_ENV}/rootfs_lightftp_coverage.ext4"
ROOTFS_SIZE_MB=256
DOCKERFILE="${FC_ENV}/Dockerfile.lightftp-rootfs-coverage"

echo "============================================================"
echo "  Building LightFTP Firecracker RootFS (COVERAGE variant)"
echo "============================================================"

mkdir -p "${FC_ENV}"

# gcov_flush.c lives in FC_ENV (build context).
cat > "${DOCKERFILE}" << 'DEOF'
# Stage 1: Build LightFTP with ASAN + gcov instrumentation + flush handler
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc make git libssl-dev libc6-dev libgnutls28-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Flush handler: constructor installs SIGTERM/SIGINT → __gcov_dump() + _exit.
COPY gcov_flush.c /tmp/gcov_flush.c

RUN cd /tmp && \
    git clone https://github.com/hfiref0x/LightFTP.git && \
    cd LightFTP && git checkout 5980ea1 && \
    cd Source/Release && \
    gcc -fsanitize=address -static-libasan -fprofile-arcs -ftest-coverage -g -O2 -c ../*.c -I.. && \
    gcc -fsanitize=address -static-libasan -fprofile-arcs -ftest-coverage -g -O2 -c /tmp/gcov_flush.c -o gcov_flush.o && \
    gcc -fsanitize=address -static-libasan -fprofile-arcs -ftest-coverage -g -O2 -o fftp *.o gcov_flush.o -lpthread -lgnutls && \
    cp fftp /usr/local/bin/fftp && chmod +x /usr/local/bin/fftp

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 libssl3 libgnutls30 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/fftp /usr/local/bin/fftp

# Keep the build tree (.gcno + source) on the persistent rootfs for host lcov.
COPY --from=builder /tmp/LightFTP /opt/lightftp-build

RUN mkdir -p /tmp/ftp_root && \
    printf '[ftpconfig]\nport=21\ninterface=0.0.0.0\nexternal_ip=172.16.0.2\nlocal_mask=255.255.255.0\nminport=1024\nmaxport=65535\nmaxusers=100\nmaxcmds=999999\n\n[admin]\npswd=*\naccs=admin\nroot=/tmp/ftp_root\n' > /etc/fftp.conf

# /init: run ffp in the BACKGROUND so a watchdog (shell builtin kill — no
# external kill binary needed) can SIGTERM it after the coverage duration,
# firing gcov_flush's __gcov_dump(); then sync() persists .gcda to the rootfs
# ext4 before PID-1 exit → guest halt. Duration from kernel cmdline
# cov_duration=N (host sets per campaign); default 60s.
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
mkdir -p /opt/cov\n\
export GCOV_PREFIX=/opt/cov\n\
export ASAN_OPTIONS=disable_coredump=1:abort_on_error=1:halt_on_error=0\n\
DUR=$(grep -o "cov_duration=[0-9]*" /proc/cmdline 2>/dev/null | cut -d= -f2)\n\
DUR=${DUR:-10}\n\
echo "LIFA-Fuzz: LightFTP ready (ASAN+gcov, flush in ${DUR}s)"\n\
/usr/local/bin/fftp /etc/fftp.conf &\n\
FPID=$!\n\
( sleep $DUR; kill -TERM $FPID ) &\n\
wait $FPID\n\
sync\n' > /init && chmod +x /init
DEOF

# ── Build Docker image ─────────────────────────────────────────────────────

echo ""
echo "Building Docker image..."
docker build -t lifa-lightftp-coverage -f "${DOCKERFILE}" "${FC_ENV}" > /dev/null

# ── Export to ext4 ──────────────────────────────────────────────────────────

echo "Exporting to ext4 (${ROOTFS_SIZE_MB}MB)..."

WORK_DIR=$(mktemp -d)

docker run --rm --privileged \
  -v "${FC_ENV}:/output" \
  -v "${WORK_DIR}:/work" \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  lifa-lightftp-coverage:latest \
  bash -c "
set -e
cd /
tar cf /work/rootfs.tar --exclude=./proc --exclude=./sys --exclude=./dev/pts --exclude=./output --exclude=./work .
dd if=/dev/zero of=/output/rootfs_lightftp_coverage.ext4 bs=1M count=${ROOTFS_SIZE_MB} status=none
mkfs.ext4 -F -q /output/rootfs_lightftp_coverage.ext4
mkdir -p /mnt/rootfs
mount -o loop /output/rootfs_lightftp_coverage.ext4 /mnt/rootfs
tar xf /work/rootfs.tar -C /mnt/rootfs
umount /mnt/rootfs
rm -f /work/rootfs.tar
# Own the output as the host user so the (non-root) Firecracker process can
# read AND write it (coverage needs rw to persist .gcda into the rootfs).
chown \"\${HOST_UID}:\${HOST_GID}\" /output/rootfs_lightftp_coverage.ext4
"

rm -rf "${WORK_DIR}" "${DOCKERFILE}"

echo ""
echo "✓ LightFTP Coverage RootFS: ${OUTPUT}"
echo "  Size: $(du -h "${OUTPUT}" | cut -f1)"
echo ""
echo "  LightFTP: ASAN + gcov (-fprofile-arcs -ftest-coverage) + flush handler"
echo "  Coverage data: /opt/cov/*.gcda (flushed on CtrlAltDel→SIGINT)"
echo "  Build artifacts: /opt/lightftp-build/ (.gcno + source for host lcov)"
echo ""
echo "============================================================"
