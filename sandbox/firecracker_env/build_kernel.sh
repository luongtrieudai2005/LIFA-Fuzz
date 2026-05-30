#!/usr/bin/env bash
# =============================================================================
# build_kernel.sh
# ────────────────
# Downloads and builds a minimal Linux kernel (vmlinux) for Firecracker.
#
# Uses the recommended microvm config from the firecracker project:
#   https://github.com/firecracker-microvm/machine-config-spec
#
# Output: sandbox/firecracker_env/vmlinux
#
# Usage:
#   bash sandbox/firecracker_env/build_kernel.sh
#
# Prerequisites:
#   gcc, make, flex, bison, libelf-dev, libssl-dev, bc, cpio
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_VERSION="6.1.132"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz"
KERNEL_SRC="${SCRIPT_DIR}/linux-${KERNEL_VERSION}"
OUTPUT="${SCRIPT_DIR}/vmlinux"

echo "============================================================"
echo "  Building Firecracker Kernel v${KERNEL_VERSION}"
echo "============================================================"

# ── Download ──────────────────────────────────────────────────────────────────

if [[ ! -f "${OUTPUT}" ]]; then
    if [[ ! -d "${KERNEL_SRC}" ]]; then
        echo ""
        echo "Downloading kernel ${KERNEL_VERSION}..."
        curl -fSL -o "${SCRIPT_DIR}/linux.tar.xz" "${KERNEL_URL}"
        echo "Extracting..."
        tar -xf "${SCRIPT_DIR}/linux.tar.xz" -C "${SCRIPT_DIR}"
        rm -f "${SCRIPT_DIR}/linux.tar.xz"
    fi

    cd "${KERNEL_SRC}"

    # ── Configure for microvm ─────────────────────────────────────────────

    echo ""
    echo "Configuring kernel for Firecracker microvm..."

    # Start with tinyconfig as base (absolute minimum)
    make tinyconfig

    # Append Firecracker-required options
    cat >> .config << 'EOF'

# === Firecracker required ===
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_PRINTK=y
CONFIG_TTY=y
CONFIG_VT=n
CONFIG_HW_RANDOM=n

# ACPI required for virtio-mmio device discovery on x86_64.
# Firecracker provides ACPI DSDT tables describing its MMIO devices.
# On x86, ACPI depends on PCI (build-time Kconfig dependency).
# At runtime, pci=off skips PCI bus scanning — ACPI still works.
CONFIG_PCI=y
CONFIG_ACPI=y
CONFIG_PCI_GOANY=y

CONFIG_USB=n
CONFIG_VIRTIO=y
CONFIG_VIRTIO_MENU=y
CONFIG_VIRTIO_MMIO=y
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_NET=y
CONFIG_VIRTIO_PCI=n
CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y
CONFIG_NETDEVICES=y
CONFIG_NET_CORE=y
CONFIG_ETHERNET=y
CONFIG_INET=y
CONFIG_NET=y
CONFIG_IP_PNP=y
CONFIG_UNIX=y
CONFIG_PACKET=y
CONFIG_VETH=y
CONFIG_BRIDGE=y
CONFIG_TUN=y
CONFIG_DUMMY=y
CONFIG_PROC_FS=y
CONFIG_SYSFS=y
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_TMPFS=y
CONFIG_SIGNALFD=y
CONFIG_TIMERFD=y
CONFIG_EPOLL=y
CONFIG_INOTIFY_USER=y
CONFIG_FUTEX=y
CONFIG_SHMEM=y
CONFIG_BLOCK=y
CONFIG_EXT4_FS=y
CONFIG_JBD2=y
CONFIG_CRC16=y
CONFIG_MSDOS_PARTITION=y
CONFIG_SYSVIPC=y
CONFIG_BINFMT_ELF=y
CONFIG_BINFMT_SCRIPT=y
CONFIG_64BIT=y
CONFIG_SMP=y
CONFIG_SCHED_OMIT_FRAME_POINTER=y
CONFIG_HYPERVISOR_GUEST=y
CONFIG_KVM_GUEST=y
CONFIG_PARAVIRT=y
CONFIG_PARAVIRT_CLOCK=y
CONFIG_HIGHMEM64G=y
CONFIG_NR_CPUS=2
CONFIG_MEMCG=n
CONFIG_CGROUPS=n
EOF

    # Resolve dependencies
    make olddefconfig

    # ── Build ─────────────────────────────────────────────────────────────

    echo ""
    echo "Building kernel ($(nproc) jobs)..."
    make -j"$(nproc)" vmlinux 2>&1 | tail -5

    # Copy output
    cp vmlinux "${OUTPUT}"
    echo ""
    echo "✓ Kernel built: ${OUTPUT}"
    echo "  Size: $(du -h "${OUTPUT}" | cut -f1)"
else
    echo ""
    echo "Kernel already exists: ${OUTPUT}"
    echo "  Size: $(du -h "${OUTPUT}" | cut -f1)"
    echo "  Delete ${OUTPUT} to rebuild."
fi

echo "============================================================"
