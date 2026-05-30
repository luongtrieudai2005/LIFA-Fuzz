#!/usr/bin/env bash
# =============================================================================
# setup_firecracker.sh
# ─────────────────────
# Downloads the official Firecracker release binary into sandbox/firecracker_env/.
#
# This is the FIRST step in the Docker → Firecracker migration.
# Kernels, rootfs images, and jailer setup come in later steps.
#
# Usage:
#   bash sandbox/setup_firecracker.sh          # downloads v1.7.0 (default)
#   bash sandbox/setup_firecracker.sh v1.8.0   # downloads a specific tag
#
# Prerequisites:
#   - curl or wget
#   - tar
#   - uname -m returns x86_64 or aarch64
#
# After running:
#   sandbox/firecracker_env/firecracker         → the MicroVM monitor binary
#   sandbox/firecracker_env/jailer              → the jailer binary (seccomp/chroot isolation)
#   sandbox/firecracker_env/release-<tag>-<arch>/ → extracted release archive
# =============================================================================

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────

DEFAULT_VERSION="v1.7.0"
VERSION="${1:-$DEFAULT_VERSION}"
ARCH="$(uname -m)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${SCRIPT_DIR}/firecracker_env"

GITHUB_BASE="https://github.com/firecracker-microvm/firecracker/releases/download"

# ── Validate architecture ────────────────────────────────────────────────────

case "${ARCH}" in
    x86_64)  FC_ARCH="x86_64" ;;
    aarch64) FC_ARCH="aarch64" ;;
    *)
        echo "ERROR: Unsupported architecture '${ARCH}'. Firecracker requires x86_64 or aarch64."
        exit 1
        ;;
esac

# ── Banner ───────────────────────────────────────────────────────────────────

echo "============================================================"
echo "  Firecracker Setup — LIFA-Fuzz Sandbox Migration"
echo "============================================================"
echo "  Version:     ${VERSION}"
echo "  Architecture:${FC_ARCH}"
echo "  Install dir: ${INSTALL_DIR}"
echo "============================================================"

# ── Create install directory ─────────────────────────────────────────────────

mkdir -p "${INSTALL_DIR}"

# ── Check if already downloaded ──────────────────────────────────────────────

BINARY="${INSTALL_DIR}/firecracker"
JAILER="${INSTALL_DIR}/jailer"

if [[ -x "${BINARY}" ]]; then
    EXISTING_VERSION="$("${BINARY}" --version 2>/dev/null | head -1 || echo 'unknown')"
    echo ""
    echo "Firecracker binary already exists: ${BINARY}"
    echo "  Version: ${EXISTING_VERSION}"
    echo ""
    echo "To re-download, delete ${INSTALL_DIR} and re-run this script."
    exit 0
fi

# ── Download release archive ─────────────────────────────────────────────────

ARCHIVE_NAME="firecracker-${VERSION}-${FC_ARCH}.tgz"
DOWNLOAD_URL="${GITHUB_BASE}/${VERSION}/${ARCHIVE_NAME}"

echo ""
echo "Downloading: ${DOWNLOAD_URL}"

TGZ_PATH="${INSTALL_DIR}/${ARCHIVE_NAME}"

if command -v curl &>/dev/null; then
    curl -fSL -o "${TGZ_PATH}" "${DOWNLOAD_URL}"
elif command -v wget &>/dev/null; then
    wget -O "${TGZ_PATH}" "${DOWNLOAD_URL}"
else
    echo "ERROR: Neither curl nor wget found. Please install one."
    exit 1
fi

# ── Extract ──────────────────────────────────────────────────────────────────

EXTRACT_DIR="${INSTALL_DIR}/release-${VERSION}-${FC_ARCH}"
mkdir -p "${EXTRACT_DIR}"

echo "Extracting to ${EXTRACT_DIR}..."
tar -xzf "${TGZ_PATH}" -C "${EXTRACT_DIR}" --strip-components=1

# ── Copy binaries to install root ────────────────────────────────────────────

# The archive contains: firecracker, jailer, jailer/{seccomp filters}, etc.
# We copy the main binaries to ${INSTALL_DIR}/ for easy access.

for bin in firecracker jailer; do
    # Try exact name first, then version-suffixed name
    src="${EXTRACT_DIR}/${bin}"
    if [[ ! -f "${src}" ]]; then
        src="${EXTRACT_DIR}/${bin}-${VERSION}-${FC_ARCH}"
    fi
    if [[ -f "${src}" ]]; then
        cp "${src}" "${INSTALL_DIR}/${bin}"
        chmod +x "${INSTALL_DIR}/${bin}"
        echo "  ✓ ${bin} → ${INSTALL_DIR}/${bin}"
    else
        echo "  ⚠ ${bin} not found in archive (tried: '${bin}' and '${bin}-${VERSION}-${FC_ARCH}')"
    fi
done

# ── Cleanup archive ─────────────────────────────────────────────────────────

rm -f "${TGZ_PATH}"

# ── Verify ───────────────────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  Verification"
echo "============================================================"

if [[ -x "${BINARY}" ]]; then
    echo "  firecracker: $("${BINARY}" --version 2>&1 | head -1)"
else
    echo "  ERROR: firecracker binary not found or not executable"
    exit 1
fi

if [[ -x "${JAILER}" ]]; then
    echo "  jailer:      $(basename "${JAILER}") present"
fi

echo ""
echo "  Installation complete!"
echo "  Binary location: ${BINARY}"
echo ""
echo "  Next steps (NOT yet automated):"
echo "    1. Build/download a vmlinux kernel"
echo "    2. Build a rootfs ext4 image with the target server"
echo "    3. Update config.yaml: sandbox.driver → \"firecracker\""
echo "============================================================"
