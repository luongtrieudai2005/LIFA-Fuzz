#!/usr/bin/env bash
# =============================================================================
# build_rootfs_lightftp_tsan.sh
# ─────────────────────────────────────────────
# ThreadSanitizer (TSAN) build for the LightFTP Firecracker rootfs.
#
# WHY TSAN, NOT ASAN: the target is CVE-2023-24042 (LightFTP @ 85c6a90,
# parent of fix 084baa7), which is a RACE CONDITION (CWE-362) on the shared
# per-connection stack context — worker threads (list/retr/stor/mlsd/append)
# are spawned with `pthread_create(..., fn, &ctx)` and read ctx.FileName /
# ctx.DataSocket / ctx.File while the control thread can run
# ftp_worker_thread_cleanup + overwrite those same fields on the next command.
# AddressSanitizer/UBSan do NOT detect data races; ThreadSanitizer does.
# The fix (084baa7) copies the context into a per-thread PTHCONTEXT.
#
# This build uses -fsanitize=thread and runs with TSAN_OPTIONS=halt_on_error=1,
# so the first detected data race aborts the process and the "WARNING:
# ThreadSanitizer: data race" report lands on the Firecracker serial console,
# where the crash monitor picks it up.
#
# Output: sandbox/firecracker_env/rootfs_lightftp.ext4  (the ACTIVE lightftp
# target — `--target lightftp` loads this). The ASAN variant
# (build_rootfs_lightftp.sh) writes the same path; the last build wins.
# ASAN image preserved separately as rootfs_lightftp_asan.ext4.
#
# Usage:
#   bash scripts/build_rootfs_lightftp_tsan.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FC_ENV="${PROJECT_ROOT}/sandbox/firecracker_env"
OUTPUT="${FC_ENV}/rootfs_lightftp.ext4"
ROOTFS_SIZE_MB=256
DOCKERFILE="${FC_ENV}/Dockerfile.lightftp-tsan"

echo "============================================================"
echo "  Building LightFTP Firecracker RootFS (TSAN variant)"
echo "============================================================"

mkdir -p "${FC_ENV}"

cat > "${DOCKERFILE}" << 'DEOF'
# LightFTP @ commit 85c6a90 = parent of the CVE-2023-24042 fix (084baa7).
# Built with ThreadSanitizer (NOT AddressSanitizer): CVE-2023-24042 is a data
# race on the shared per-connection context, which ASAN cannot detect.
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc make git libssl-dev libc6-dev libgnutls28-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN cd /tmp && \
    git clone https://github.com/hfiref0x/LightFTP.git && \
    cd LightFTP && git checkout 85c6a90 && \
    cd Source/Release && \
    gcc -fsanitize=thread -static-libtsan -no-pie -fno-PIE -g -O1 -c ../*.c -I.. && \
    gcc -fsanitize=thread -static-libtsan -no-pie -fno-PIE -g -O1 -o fftp *.o -lpthread -lgnutls && \
    cp ffp /usr/local/bin/fftp && chmod +x /usr/local/bin/fftp

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 libssl3 libgnutls30 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/fftp /usr/local/bin/fftp

RUN mkdir -p /tmp/ftp_root && \
    printf '[ftpconfig]\nport=21\ninterface=0.0.0.0\nexternal_ip=172.16.0.2\nlocal_mask=255.255.255.0\nminport=1024\nmaxport=65535\nmaxusers=10\nmaxcmds=999999\n\n[admin]\npswd=*\naccs=admin\nroot=/tmp/ftp_root\n' > /etc/fftp.conf

# halt_on_error=1 → abort (exit) on the first reported race so the crash
# monitor sees the process die + the TSAN report on the serial console.
# No ASLR toggle needed: ffp is built -no-pie, so its text loads at a fixed
# address and TSAN's fixed shadow layout no longer collides with it.
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
echo "LIFA-Fuzz: LightFTP ready on 172.16.0.2:21 (TSAN enabled)"\n\
export TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1\n\
exec /usr/local/bin/fftp /etc/fftp.conf\n' > /init && chmod +x /init
DEOF

# ── Build Docker image ─────────────────────────────────────────────────────

echo ""
echo "Building Docker image..."
docker build -t lifa-lightftp-tsan -f "${DOCKERFILE}" "${FC_ENV}" > /dev/null

# ── Export to ext4 via Docker privileged container ──────────────────────────

echo "Exporting to ext4 (${ROOTFS_SIZE_MB}MB)..."

WORK_DIR=$(mktemp -d)

docker run --rm --privileged \
  -v "${FC_ENV}:/output" \
  -v "${WORK_DIR}:/work" \
  lifa-lightftp-tsan:latest \
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
echo "✓ LightFTP TSAN RootFS: ${OUTPUT}"
echo "  Size: $(du -h "${OUTPUT}" | cut -f1)"
echo ""
echo "  LightFTP @ 85c6a90: -fsanitize=thread (CVE-2023-24042 race detector)"
echo "  Active target: --target lightftp loads this rootfs (rootfs_lightftp.ext4)"
echo ""
echo "  Launch:"
echo "    python3 main.py --driver firecracker --target lightftp"
echo ""
echo "============================================================"
