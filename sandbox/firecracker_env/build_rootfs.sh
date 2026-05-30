#!/usr/bin/env bash
# =============================================================================
# build_rootfs.sh
# ────────────────
# Builds a minimal ext4 root filesystem for Firecracker with the vulnerable
# LIFA server binary and a simple /init that sets up networking and launches it.
#
# Output: sandbox/firecracker_env/rootfs.ext4
#
# Usage:
#   bash sandbox/firecracker_env/build_rootfs.sh
#
# Prerequisites:
#   gcc (with static linking support), e2fsprogs (mkfs.ext4)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TARGET_SRC="${PROJECT_ROOT}/sandbox/target/vulnerable_server.c"
ROOTFS_DIR="${SCRIPT_DIR}/rootfs_staging"
OUTPUT="${SCRIPT_DIR}/rootfs.ext4"
ROOTFS_SIZE_MB=32

# Network config inside the VM (matches driver defaults)
VM_IP="172.16.0.2"
VM_GW="172.16.0.1"
VM_NETMASK="255.255.255.0"
VM_PORT=9000

echo "============================================================"
echo "  Building Firecracker RootFS"
echo "============================================================"

# ── Build vulnerable server (static) ─────────────────────────────────────────

echo ""
echo "Compiling vulnerable_server (static)..."

SERVER_BIN="${SCRIPT_DIR}/vulnerable_server"
gcc -O0 -fno-stack-protector -z execstack -no-pie -static \
    -o "${SERVER_BIN}" \
    "${TARGET_SRC}"
echo "  ✓ ${SERVER_BIN} ($(du -h "${SERVER_BIN}" | cut -f1))"

# ── Download static BusyBox ────────────────────────────────────────────────

echo ""
echo "Downloading static BusyBox..."

BUSYBOX_URL="https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"
BUSYBOX_BIN="${SCRIPT_DIR}/busybox"

if [[ ! -f "${BUSYBOX_BIN}" ]]; then
    curl -fSL -o "${BUSYBOX_BIN}" "${BUSYBOX_URL}"
    chmod +x "${BUSYBOX_BIN}"
fi
echo "  ✓ ${BUSYBOX_BIN} ($(du -h "${BUSYBOX_BIN}" | cut -f1))"

# ── Create staging directory ────────────────────────────────────────────────

echo ""
echo "Creating rootfs staging directory..."
rm -rf "${ROOTFS_DIR}"
mkdir -p "${ROOTFS_DIR}"/{bin,sbin,etc,proc,sys,dev,tmp,usr/bin,usr/sbin,var/run}

# ── Install server binary ───────────────────────────────────────────────────

cp "${SERVER_BIN}" "${ROOTFS_DIR}/bin/vulnerable_server"
chmod +x "${ROOTFS_DIR}/bin/vulnerable_server"
echo "  ✓ /bin/vulnerable_server installed"

# ── Install BusyBox + symlinks ──────────────────────────────────────────────

cp "${BUSYBOX_BIN}" "${ROOTFS_DIR}/bin/busybox"
chmod +x "${ROOTFS_DIR}/bin/busybox"

# Create essential symlinks
for cmd in sh mount umount ip ln ls cat echo mkdir mknod sleep poweroff reboot; do
    ln -s busybox "${ROOTFS_DIR}/bin/${cmd}"
done
echo "  ✓ BusyBox installed with symlinks"

# ── Create minimal /init ────────────────────────────────────────────────────

cat > "${ROOTFS_DIR}/init" << 'INIT_EOF'
#!/bin/sh
# /init — MicroVM bootstrap for LIFA-Fuzz target server
# Runs as PID 1 inside the Firecracker VM.

# Mount essential pseudo-filesystems
mount -t proc     proc     /proc
mount -t sysfs    sysfs    /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs    tmpfs    /tmp

# Bring up loopback
ip link set lo up

# Bring up eth0 with static IP (passed via kernel args or defaults)
VM_IP="${1:-172.16.0.2}"
VM_GW="${2:-172.16.0.1}"
VM_MASK="${3:-255.255.255.0}"

ip addr add "${VM_IP}/24" dev eth0
ip link set eth0 up
ip route add default via "${VM_GW}"

echo "╔══════════════════════════════════════════════════╗"
echo "║  LIFA-Fuzz Firecracker Target VM                ║"
echo "║  IP: ${VM_IP}  GW: ${VM_GW}            ║"
echo "║  Starting vulnerable_server on port 9000...     ║"
echo "╚══════════════════════════════════════════════════╝"

# Launch the vulnerable server (foreground — PID 1 is the server)
# If the server crashes, the VM exits (detected by the driver).
exec /bin/vulnerable_server
INIT_EOF

chmod +x "${ROOTFS_DIR}/init"
echo "  ✓ /init created"

# ── Create minimal /etc files ───────────────────────────────────────────────

# passwd (needed for some libc functions)
echo "root:x:0:0:root:/root:/bin/sh" > "${ROOTFS_DIR}/etc/passwd"
echo "root:x:0:" > "${ROOTFS_DIR}/etc/group"

# nsswitch.conf
echo "passwd: files" > "${ROOTFS_DIR}/etc/nsswitch.conf"
echo "group:  files" >> "${ROOTFS_DIR}/etc/nsswitch.conf"

# hostname
echo "lifa-target" > "${ROOTFS_DIR}/etc/hostname"

echo "  ✓ /etc files created"

# ── Build ext4 image ────────────────────────────────────────────────────────

echo ""
echo "Building ext4 image (${ROOTFS_SIZE_MB}MB)..."

# Create sparse file
dd if=/dev/zero of="${OUTPUT}" bs=1M count="${ROOTFS_SIZE_MB}" status=none

# Format as ext4
mkfs.ext4 -F -q "${OUTPUT}"

# ── Copy files using debugfs (no root required) ─────────────────────────
# debugfs is part of e2fsprogs and can write to ext4 images without mounting.

# Build a debugfs command script
DEBUGFS_SCRIPT=$(mktemp)
echo "" > "${DEBUGFS_SCRIPT}"

# Recursively add all files from the staging directory
while IFS= read -r -d '' f; do
    REL_PATH="${f#${ROOTFS_DIR}}"
    DIR_NAME=$(dirname "${REL_PATH}")
    BASE_NAME=$(basename "${REL_PATH}")

    # Create parent directories
    if [[ "${DIR_NAME}" != "/" && "${DIR_NAME}" != "" ]]; then
        echo "mkdir ${DIR_NAME}" >> "${DEBUGFS_SCRIPT}"
    fi

    # Write the file into the image
    echo "write ${f} ${REL_PATH}" >> "${DEBUGFS_SCRIPT}"
done < <(find "${ROOTFS_DIR}" -type f -print0)

# Execute debugfs
if command -v debugfs &>/dev/null; then
    debugfs -w -f "${DEBUGFS_SCRIPT}" "${OUTPUT}" >/dev/null 2>&1
    rm -f "${DEBUGFS_SCRIPT}"
    echo "  ✓ Files written via debugfs (no sudo needed)"
else
    rm -f "${DEBUGFS_SCRIPT}"
    # Fallback: try guestfish, then mount
    if command -v guestfish &>/dev/null; then
        echo "  Using guestfish..."
        guestfish -a "${OUTPUT}" <<EOF
run
mount /dev/sda /
copy-in ${ROOTFS_DIR}/* /
EOF
    else
        # Last resort: try mount with sudo
        echo "  Neither debugfs nor guestfish found — trying sudo mount..."
        MOUNT_POINT=$(mktemp -d)
        sudo mount -o loop "${OUTPUT}" "${MOUNT_POINT}"
        sudo cp -a "${ROOTFS_DIR}"/* "${MOUNT_POINT}/"
        sudo umount "${MOUNT_POINT}"
        rmdir "${MOUNT_POINT}"
    fi
fi

echo ""
echo "✓ RootFS built: ${OUTPUT}"
echo "  Size: $(du -h "${OUTPUT}" | cut -f1)"
echo "  Contents: $(find "${ROOTFS_DIR}" -type f | wc -l) files"

# ── Cleanup staging ─────────────────────────────────────────────────────────

rm -rf "${ROOTFS_DIR}"
echo ""
echo "============================================================"
