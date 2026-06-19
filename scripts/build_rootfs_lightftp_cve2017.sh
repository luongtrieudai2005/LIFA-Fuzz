#!/usr/bin/env bash
# =============================================================================
# build_rootfs_lightftp_cve2017.sh
# ─────────────────────────────────────────────
# LightFTP @ commit e7deedc — CVE-2017-1000218 (writelogentry _text[512] + strcat).
# POSIX code in Source/Other/ (buildable, ASAN-instrumented).
# The overflow is in the USER command handler — the FIRST command of every FTP
# session. No vulnerability-specific seeding needed.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FC_ENV="${PROJECT_ROOT}/sandbox/firecracker_env"
OUTPUT="${FC_ENV}/rootfs_lightftp.ext4"
ROOTFS_SIZE_MB=256
DOCKERFILE="${FC_ENV}/Dockerfile.lightftp-cve2017"

echo "============================================================"
echo "  Building LightFTP @ e7deedc (CVE-2017-1000218) RootFS"
echo "============================================================"
mkdir -p "${FC_ENV}"

cat > "${DOCKERFILE}" << 'DEOF'
# LightFTP @ e7deedc = CVE-2017-1000218 (writelogentry _text[512] + strcat).
# Source/Other/ is the POSIX code tree (Release/ + .c files). The overflow is
# in writelogentry: char _text[512]; strcat(_text, logtext2) where logtext2 is
# the USER argument (network-controlled). USER > ~480 bytes → stack overflow.
FROM debian:bookworm-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc make git libc6-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN cd /tmp && \
    git clone https://github.com/hfiref0x/LightFTP.git && \
    cd LightFTP && git checkout e7deedc && \
    cd Source/Other/Release && \
    gcc -fsanitize=address -static-libasan -g -O1 -fno-stack-protector -fcommon -c ../*.c -I.. && \
    gcc -fsanitize=address -static-libasan -g -O1 -fno-stack-protector -fcommon -o fftp *.o -lpthread -Wl,--allow-multiple-definition && \
    cp fftp /usr/local/bin/fftp && chmod +x /usr/local/bin/fftp

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/bin/fftp /usr/local/bin/fftp
RUN mkdir -p /tmp/ftp_root && \
    printf '[ftpconfig]\nport=21\ninterface=0.0.0.0\nexternal_ip=172.16.0.2\nlocal_mask=255.255.255.0\nminport=1024\nmaxport=65535\nmaxusers=10\nlogfilepath=/tmp/fftp.log\n\n[anonymous]\npswd=*\naccs=admin\nroot=/tmp/ftp_root\n' > /etc/fftp.conf
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
export ASAN_OPTIONS=disable_coredump=1:abort_on_error=1:halt_on_error=1:detect_leaks=0:detect_odr_violation=0\n\
exec /usr/local/bin/fftp /etc/fftp.conf </dev/zero\n' > /init && chmod +x /init
DEOF

echo "Building Docker image..."
docker build -t lifa-lightftp-cve2017 -f "${DOCKERFILE}" "${FC_ENV}" 2>&1 | tail -20

echo "Exporting to ext4 (${ROOTFS_SIZE_MB}MB)..."
WORK_DIR=$(mktemp -d)
docker run --rm --privileged \
  -v "${FC_ENV}:/output" \
  -v "${WORK_DIR}:/work" \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  lifa-lightftp-cve2017:latest \
  bash -c "
set -e
cd /
tar cf /work/rootfs.tar --exclude=./proc --exclude=./sys --exclude=./dev/pts --exclude=./output --exclude=./work .
dd if=/dev/zero of=/output/rootfs_lightftp.ext4 bs=1M count=${ROOTFS_SIZE_MB} status=none
mkfs.ext4 -F -q /output/rootfs_lightftp.ext4
mkdir -p /mnt/rootfs
mount -o loop /output/rootfs_lightftp.ext4 /mnt/rootfs
tar xf /work/rootfs.tar -C /mnt/rootfs
sync
umount /mnt/rootfs
chown \"\${HOST_UID}:\${HOST_GID}\" /output/rootfs_lightftp.ext4
"
rm -rf "${WORK_DIR}" "${DOCKERFILE}"
echo ""
echo "✓ LightFTP CVE-2017 RootFS: ${OUTPUT} ($(du -h "${OUTPUT}" | cut -f1))"
echo "  writelogentry _text[512] + strcat → USER arg >480B → ASAN stack overflow"
echo "============================================================"
