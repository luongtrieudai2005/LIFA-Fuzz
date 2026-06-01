#!/usr/bin/env bash
# =============================================================================
# prepare_lighttpd.sh — Download, patch, and compile lighttpd for LIFA-Fuzz
# =============================================================================
# Builds lighttpd with gcov instrumentation for coverage-guided fuzzing.
#
# Usage:
#   ./scripts/prepare_lighttpd.sh              # Build with coverage
#   ./scripts/prepare_lighttpd.sh --no-cov     # Build without coverage
#   ./scripts/prepare_lighttpd.sh --clean      # Remove build artifacts
#
# Output:
#   tests/dummy_targets/real_targets/lighttpd/lighttpd_cov  (coverage binary)
#   tests/dummy_targets/real_targets/lighttpd/lighttpd_bin  (plain binary)
#
# Requirements:
#   - gcc, make, autoconf, automake, libtool, pkg-config
#   - Internet access (downloads source tarball)
# =============================================================================
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
LIGHTTPD_VERSION="1.4.55"
LIGHTTPD_TARBALL="lighttpd-${LIGHTTPD_VERSION}.tar.gz"
LIGHTTPD_URL="https://download.lighttpd.net/lighttpd/releases-1.4.x/${LIGHTTPD_TARBALL}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_DIR="${PROJECT_ROOT}/tests/dummy_targets/real_targets/lighttpd"
BUILD_DIR="${TARGET_DIR}/build"
DOCROOT="${TARGET_DIR}/docroot"

# Coverage flags
COV_CFLAGS="-fprofile-arcs -ftest-coverage -O0 -g -fno-stack-protector"
COV_LDFLAGS="-lgcov --coverage"

# ── Parse arguments ──────────────────────────────────────────────────────────
WITH_COV=true
CLEAN=false

for arg in "$@"; do
    case "${arg}" in
        --no-cov)  WITH_COV=false ;;
        --clean)   CLEAN=true ;;
        --help|-h)
            echo "Usage: $0 [--no-cov] [--clean] [--help]"
            echo ""
            echo "  --no-cov   Build without coverage instrumentation"
            echo "  --clean    Remove build artifacts and downloaded sources"
            echo "  --help     Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown argument: ${arg}" >&2
            exit 1
            ;;
    esac
done

# ── Clean mode ───────────────────────────────────────────────────────────────
if ${CLEAN}; then
    echo "→ Cleaning lighttpd build artifacts..."
    rm -rf "${BUILD_DIR}" "${TARGET_DIR}/lighttpd_cov" "${TARGET_DIR}/lighttpd_bin"
    rm -rf "${TARGET_DIR}"/*.gcda "${TARGET_DIR}"/*.gcno
    echo "✓ Clean complete."
    exit 0
fi

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  LIFA-Fuzz — lighttpd ${LIGHTTPD_VERSION} Target Preparation          ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# ── Check prerequisites ─────────────────────────────────────────────────────
echo "→ Checking prerequisites..."

_check_cmd() {
    if ! command -v "$1" &>/dev/null; then
        echo "✗ Missing: $1 — install with: sudo apt install $2" >&2
        return 1
    fi
    echo "  ✓ $1"
}

MISSING=false
_check_cmd gcc   "build-essential" || MISSING=true
_check_cmd make  "build-essential" || MISSING=true
_check_cmd autoconf "autoconf automake libtool" || MISSING=true
_check_cmd automake "autoconf automake libtool" || MISSING=true

if ${MISSING}; then
    echo ""
    echo "ERROR: Missing prerequisites. Install them and re-run." >&2
    exit 1
fi

# ── Download source ──────────────────────────────────────────────────────────
mkdir -p "${BUILD_DIR}"

if [ ! -f "${BUILD_DIR}/${LIGHTTPD_TARBALL}" ]; then
    echo ""
    echo "→ Downloading lighttpd ${LIGHTTPD_VERSION}..."
    curl -L -o "${BUILD_DIR}/${LIGHTTPD_TARBALL}" "${LIGHTTPD_URL}"
    if [ ! -f "${BUILD_DIR}/${LIGHTTPD_TARBALL}" ]; then
        echo "ERROR: Download failed. Check your internet connection." >&2
        exit 1
    fi
    echo "  ✓ Downloaded ${LIGHTTPD_TARBALL}"
else
    echo "  ✓ Source tarball already downloaded"
fi

# ── Extract ──────────────────────────────────────────────────────────────────
SRC_DIR="${BUILD_DIR}/lighttpd-${LIGHTTPD_VERSION}"

if [ ! -d "${SRC_DIR}" ]; then
    echo ""
    echo "→ Extracting source..."
    tar xzf "${BUILD_DIR}/${LIGHTTPD_TARBALL}" -C "${BUILD_DIR}"
    echo "  ✓ Extracted to ${SRC_DIR}"
else
    echo "  ✓ Source already extracted"
fi

# ── Configure ────────────────────────────────────────────────────────────────
echo ""
echo "→ Configuring lighttpd ${LIGHTTPD_VERSION}..."

cd "${SRC_DIR}"

# Run autogen if needed (some tarballs ship without configure)
if [ ! -f "./configure" ]; then
    echo "  Running ./autogen.sh..."
    ./autogen.sh 2>/dev/null || true
fi

# Configure with minimal features for a lean attack surface
if ${WITH_COV}; then
    echo "  Coverage mode: ON (gcov instrumentation)"
    CFLAGS="${COV_CFLAGS}" LDFLAGS="${COV_LDFLAGS}" \
        ./configure \
            --prefix="${TARGET_DIR}/install" \
            --disable-ssl \
            --disable-lfs \
            --without-pcre \
            --without-zlib \
            --without-bzip2 \
            --without-ldap \
            --without-mysql \
            --without-pgsql \
            --without-kerberos5 \
            --without-attr \
            --without-valgrind \
            --without-fam \
            --without-libev \
            --without-libunwind \
            --without-maxminddb \
            --without-dbi \
            --without-sasl \
            --without-xxhash
else
    echo "  Coverage mode: OFF"
    CFLAGS="-O0 -g -fno-stack-protector" \
        ./configure \
            --prefix="${TARGET_DIR}/install" \
            --disable-ssl \
            --without-pcre \
            --without-zlib \
            --without-bzip2 \
            --without-ldap \
            --without-mysql \
            --without-pgsql \
            --without-kerberos5 \
            --without-attr \
            --without-valgrind \
            --without-fam \
            --without-libev \
            --without-libunwind \
            --without-maxminddb \
            --without-dbi \
            --without-sasl \
            --without-xxhash
fi

echo "  ✓ Configure complete"

# ── Build ────────────────────────────────────────────────────────────────────
echo ""
echo "→ Building lighttpd (this may take a minute)..."

make -j"$(nproc 2>/dev/null || echo 2)"

echo "  ✓ Build complete"

# ── Install binaries ─────────────────────────────────────────────────────────
echo ""
echo "→ Installing binaries to ${TARGET_DIR}/..."

make install 2>/dev/null || true

# Copy the built binary with a descriptive name
if [ -f "${TARGET_DIR}/install/sbin/lighttpd" ]; then
    if ${WITH_COV}; then
        cp "${TARGET_DIR}/install/sbin/lighttpd" "${TARGET_DIR}/lighttpd_cov"
        echo "  ✓ Coverage binary: ${TARGET_DIR}/lighttpd_cov"
    else
        cp "${TARGET_DIR}/install/sbin/lighttpd" "${TARGET_DIR}/lighttpd_bin"
        echo "  ✓ Plain binary: ${TARGET_DIR}/lighttpd_bin"
    fi
elif [ -f "${SRC_DIR}/src/lighttpd" ]; then
    # Fallback: copy from build tree
    if ${WITH_COV}; then
        cp "${SRC_DIR}/src/lighttpd" "${TARGET_DIR}/lighttpd_cov"
        echo "  ✓ Coverage binary: ${TARGET_DIR}/lighttpd_cov"
    else
        cp "${SRC_DIR}/src/lighttpd" "${TARGET_DIR}/lighttpd_bin"
        echo "  ✓ Plain binary: ${TARGET_DIR}/lighttpd_bin"
    fi
else
    echo "WARNING: Could not locate built lighttpd binary." >&2
    echo "  Looked in:" >&2
    echo "    ${TARGET_DIR}/install/sbin/lighttpd" >&2
    echo "    ${SRC_DIR}/src/lighttpd" >&2
fi

# ── Create document root ────────────────────────────────────────────────────
mkdir -p "${DOCROOT}"
if [ ! -f "${DOCROOT}/index.html" ]; then
    cat > "${DOCROOT}/index.html" <<'HTMLEOF'
<!DOCTYPE html>
<html>
<head><title>LIFA-Fuzz Target</title></head>
<body><h1>lighttpd fuzzing target — LIFA-Fuzz</h1></body>
</html>
HTMLEOF
    echo "  ✓ Created document root: ${DOCROOT}"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  Setup Complete!                                                ║"
echo "╠══════════════════════════════════════════════════════════════════╣"

if ${WITH_COV} && [ -f "${TARGET_DIR}/lighttpd_cov" ]; then
    COV_SIZE=$(du -h "${TARGET_DIR}/lighttpd_cov" | cut -f1)
    echo "║  Coverage binary:  lighttpd_cov  (${COV_SIZE})                  ║"
    echo "║  Run with:                                                     ║"
    echo "║    lighttpd_cov -D -f lighttpd.conf                            ║"
    echo "║                                                                ║"
    echo "║  Coverage data (.gcda) will be generated in the CWD.           ║"
    echo "║  Parse with:  lcov --capture --directory . --output-file out   ║"
elif [ -f "${TARGET_DIR}/lighttpd_bin" ]; then
    BIN_SIZE=$(du -h "${TARGET_DIR}/lighttpd_bin" | cut -f1)
    echo "║  Plain binary:  lighttpd_bin  (${BIN_SIZE})                     ║"
    echo "║  Run with:                                                     ║"
    echo "║    lighttpd_bin -D -f lighttpd.conf                            ║"
fi

echo "║                                                                ║"
echo "║  Config:       ${TARGET_DIR}/lighttpd.conf"
echo "║  Document root: ${DOCROOT}"
echo "║  Listen on:     127.0.0.1:8080"
echo "╚══════════════════════════════════════════════════════════════════╝"
