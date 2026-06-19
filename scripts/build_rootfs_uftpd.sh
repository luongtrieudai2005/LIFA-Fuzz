#!/usr/bin/env bash
# =============================================================================
# build_rootfs_uftpd.sh
# ────────────────────────────
# Production build script for the uftpd Firecracker rootfs.
#
# uftpd @ commit 0fb2c031~1 (v2.10) — parent of the PORT-parser buffer-overflow
# fix (CVE: src/ftpcmd.c:handle_PORT). Built with AddressSanitizer so ASAN
# catches the stack-buffer-overflow. ASAN runs on the Firecracker guest kernel
# (unlike TSAN); this is the deterministic, attributable memory-CVE target for RQ3.
#
# Output: sandbox/firecracker_env/rootfs_uftpd.ext4 (~120MB)
#
# Usage:
#   bash scripts/build_rootfs_uftpd.sh
#
# Prerequisites: Docker (used for rootfs assembly — no host mount/sudo needed).
# If the Debian mirror intermittently 403s on libuev-dev/libite-dev, fall back to
# building libuev/libite from source (see uftpd's .travis.yml recipe).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FC_ENV="${PROJECT_ROOT}/sandbox/firecracker_env"
OUTPUT="${FC_ENV}/rootfs_uftpd.ext4"
ROOTFS_SIZE_MB=256
DOCKERFILE="${FC_ENV}/Dockerfile.uftpd-rootfs"

echo "============================================================"
echo "  Building uftpd Firecracker RootFS (ASAN, CVE PORT overflow)"
echo "============================================================"

mkdir -p "${FC_ENV}"

echo ""
echo "Building Docker image..."
docker build -t lifa-uftpd-complete -f "${DOCKERFILE}" "${FC_ENV}" > /dev/null

echo "Exporting to ext4 (${ROOTFS_SIZE_MB}MB)..."

WORK_DIR=$(mktemp -d)

docker run --rm --privileged \
  -v "${FC_ENV}:/output" \
  -v "${WORK_DIR}:/work" \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  lifa-uftpd-complete:latest \
  bash -c "
set -e
cd /
tar cf /work/rootfs.tar --exclude=./proc --exclude=./sys --exclude=./dev/pts --exclude=./output --exclude=./work .
dd if=/dev/zero of=/output/rootfs_uftpd.ext4 bs=1M count=${ROOTFS_SIZE_MB} status=none
mkfs.ext4 -F -q /output/rootfs_uftpd.ext4
mkdir -p /mnt/rootfs
mount -o loop /output/rootfs_uftpd.ext4 /mnt/rootfs
tar xf /work/rootfs.tar -C /mnt/rootfs
sync
umount /mnt/rootfs
rm -f /work/rootfs.tar
# Own as the host user so the (non-root) Firecracker process can open it RW.
chown \"\${HOST_UID}:\${HOST_GID}\" /output/rootfs_uftpd.ext4
"

rm -rf "${WORK_DIR}"

echo ""
echo "✓ uftpd RootFS: ${OUTPUT}"
echo "  Size: $(du -h "${OUTPUT}" | cut -f1)"
echo ""
echo "  uftpd @ 0fb2c031~1: ASAN-enabled, anonymous login, bound to 0.0.0.0:21"
echo "  Boot: init=/init → uftpd -n -o ftp=21,tftp=0,writable /tmp/ftp_root"
echo ""
echo "  Launch:"
echo "    LIFA_PROTOCOL_MODULE=ftp python3 -m evaluation.evaluation_runner \\"
echo "        --baseline C --driver firecracker --target uftpd"
echo ""
echo "============================================================"
