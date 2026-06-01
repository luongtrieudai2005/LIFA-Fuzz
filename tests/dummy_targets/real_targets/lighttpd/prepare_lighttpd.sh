#!/usr/bin/env bash
# =============================================================================
# prepare_lighttpd.sh
# =============================================================================
# Download and compile lighttpd 1.4.55 with gcov instrumentation for fuzzing.
#
# Produces a coverage-instrumented binary at:
#   /tmp/lifa-lighttpd-install/sbin/lighttpd
#
# Usage:
#   bash prepare_lighttpd.sh          # build from scratch
#   bash prepare_lighttpd.sh --force  # rebuild even if exists
#
# Requirements: gcc, make, wget (or curl)
# =============================================================================
set -euo pipefail

LIGHTTPD_VERSION="1.4.55"
PREFIX="/tmp/lifa-lighttpd-install"
FORCE="${1:-}"

# ── Skip if already built ──────────────────────────────────────────────────
if [ -f "$PREFIX/sbin/lighttpd" ] && [ "$FORCE" != "--force" ]; then
    echo "[skip] lighttpd already built at $PREFIX"
    echo "       Use --force to rebuild."
    exit 0
fi

echo " Building lighttpd ${LIGHTTPD_VERSION} with gcov instrumentation..."

# ── Download ───────────────────────────────────────────────────────────────
cd /tmp
ARCHIVE="lighttpd-${LIGHTTPD_VERSION}.tar.gz"
URL="https://download.lighttpd.net/lighttpd/releases-1.4.x/${ARCHIVE}"

if [ ! -f "$ARCHIVE" ]; then
    echo "  Downloading ${URL}..."
    wget -q "$URL" || {
        echo "  wget failed — trying curl..."
        curl -sL -o "$ARCHIVE" "$URL"
    }
fi

echo "  Extracting..."
tar xzf "$ARCHIVE"

# ── Configure & Build ─────────────────────────────────────────────────────
cd "lighttpd-${LIGHTTPD_VERSION}"

echo "  Configuring with --coverage flags..."
./configure \
    --prefix="$PREFIX" \
    --enable-static \
    --with-openssl=no \
    --with-pcre=no \
    --with-zlib=no \
    --with-bzip2=no \
    CFLAGS="-fprofile-arcs -ftest-coverage -O0 -g" \
    LDFLAGS="-lgcov --coverage" \
    2>&1 | tail -5

echo "  Compiling (make -j$(nproc))..."
make -j"$(nproc)" 2>&1 | tail -3

echo "  Installing to $PREFIX..."
make install 2>&1 | tail -3

# ── Verify ─────────────────────────────────────────────────────────────────
if [ -f "$PREFIX/sbin/lighttpd" ]; then
    echo "  ✓ lighttpd built successfully: $PREFIX/sbin/lighttpd"
    echo "    Coverage flags: -fprofile-arcs -ftest-coverage -O0 -g"
else
    echo "  ✗ Build failed — lighttpd binary not found at $PREFIX/sbin/lighttpd"
    exit 1
fi
