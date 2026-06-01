#!/usr/bin/env bash
# =============================================================================
# build_lighttpd_rootfs.sh
# ───────────────────────────
# Builds a Firecracker ext4 rootfs with lighttpd 1.4.55 compiled statically
# with gcov instrumentation for coverage-guided fuzzing.
#
# Output: sandbox/firecracker_env/rootfs_lighttpd.ext4
#
# Usage:
#   bash sandbox/firecracker_env/build_lighttpd_rootfs.sh
#   bash sandbox/firecracker_env/build_lighttpd_rootfs.sh --force  # rebuild
#
# Prerequisites:
#   gcc, make, wget|curl, e2fsprogs (mkfs.ext4, debugfs)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ROOTFS_DIR="${SCRIPT_DIR}/rootfs_lighttpd_staging"
OUTPUT="${SCRIPT_DIR}/rootfs_lighttpd.ext4"
ROOTFS_SIZE_MB=128

LIGHTTPD_VERSION="1.4.55"
LIGHTTPD_PREFIX="${SCRIPT_DIR}/lighttpd_install"
FORCE="${1:-}"

# ── Detect if host GCC can build lighttpd (needs < GCC 15 for K&R compat) ──
HOST_GCC_MAJOR=$(gcc -dumpversion 2>/dev/null | cut -d. -f1 || echo "0")
USE_DOCKER_BUILD=false
if [[ "${HOST_GCC_MAJOR}" -ge 15 ]]; then
    echo "  ⚠ Host GCC ${HOST_GCC_MAJOR} is too new for lighttpd ${LIGHTTPD_VERSION}."
    echo "    Using Docker build (Ubuntu 22.04 / GCC 11) instead."
    USE_DOCKER_BUILD=true
fi

# Network config inside the VM (matches driver defaults)
VM_IP="172.16.0.2"
VM_GW="172.16.0.1"

echo "============================================================"
echo "  Building Firecracker RootFS — lighttpd ${LIGHTTPD_VERSION}"
echo "============================================================"

# ── Skip if already built ──────────────────────────────────────────────────
if [[ -f "${OUTPUT}" ]] && [[ "${FORCE}" != "--force" ]]; then
    echo "  [skip] ${OUTPUT} already exists. Use --force to rebuild."
    exit 0
fi

# ── Download lighttpd source ───────────────────────────────────────────────

BUILD_DIR="${SCRIPT_DIR}/lighttpd-${LIGHTTPD_VERSION}"
ARCHIVE="lighttpd-${LIGHTTPD_VERSION}.tar.gz"
URL="https://download.lighttpd.net/lighttpd/releases-1.4.x/${ARCHIVE}"

if [[ ! -f "${SCRIPT_DIR}/${ARCHIVE}" ]]; then
    echo ""
    echo "Downloading ${URL}..."
    wget -q -O "${SCRIPT_DIR}/${ARCHIVE}" "${URL}" || {
        echo "  wget failed — trying curl..."
        curl -sL -o "${SCRIPT_DIR}/${ARCHIVE}" "${URL}"
    }
fi

echo ""
echo "Extracting..."
rm -rf "${BUILD_DIR}"
tar xzf "${SCRIPT_DIR}/${ARCHIVE}" -C "${SCRIPT_DIR}"

# ── Compile lighttpd (static + gcov) ────────────────────────────────────────

if [[ "${USE_DOCKER_BUILD}" == "true" ]]; then
    echo ""
    echo "Building lighttpd inside Docker (Ubuntu 22.04 / GCC 11)..."

    # Run the compile inside a Ubuntu 22.04 container
    docker run --rm \
        -v "${SCRIPT_DIR}/${ARCHIVE}:/src/${ARCHIVE}" \
        -v "${LIGHTTPD_PREFIX}:/install" \
        -v "${BUILD_DIR}:/build" \
        ubuntu:22.04 \
        bash -c "
            set -e
            apt-get update -qq && apt-get install -y -qq gcc make > /dev/null 2>&1
            cd /build && tar xzf /src/${ARCHIVE} --strip-components=1
            ./configure \
                --prefix=/install \
                --enable-static \
                --without-openssl --without-pcre --without-zlib --without-bzip2 \
                --without-ldap --without-mysql --without-kerberos5 \
                CFLAGS='-O0 -g -fprofile-arcs -ftest-coverage -static' \
                LDFLAGS='-lgcov --coverage -static' \
                LIBS='-lgcov' \
                2>&1 | tail -3
            make -j\$(nproc) 2>&1 | tail -3
            make install 2>&1 | tail -3
        "
    LIGHTTPD_BIN="${LIGHTTPD_PREFIX}/sbin/lighttpd"
    if [[ ! -f "${LIGHTTPD_BIN}" ]]; then
        echo "  ✗ Docker build failed — binary not found"
        exit 1
    fi
    echo "  ✓ lighttpd built via Docker: ${LIGHTTPD_BIN} ($(du -h "${LIGHTTPD_BIN}" | cut -f1))"
else
    echo ""
    echo "Configuring lighttpd with static + gcov flags..."

    cd "${BUILD_DIR}"

    ./configure \
        --prefix="${LIGHTTPD_PREFIX}" \
        --enable-static \
        --without-openssl \
        --without-pcre \
        --without-zlib \
        --without-bzip2 \
        --without-ldap \
        --without-mysql \
        --without-kerberos5 \
        CFLAGS="-O0 -g -fprofile-arcs -ftest-coverage -static" \
        LDFLAGS="-lgcov --coverage -static" \
        LIBS="-lgcov" \
        2>&1 | tail -3

    echo "Compiling (make -j$(nproc))..."
    make -j"$(nproc)" 2>&1 | tail -3

    echo "Installing to staging..."
    make install 2>&1 | tail -3

    # Verify
    LIGHTTPD_BIN="${LIGHTTPD_PREFIX}/sbin/lighttpd"
    if [[ ! -f "${LIGHTTPD_BIN}" ]]; then
        echo "  ✗ Build failed — lighttpd binary not found at ${LIGHTTPD_BIN}"
        exit 1
    fi
    echo "  ✓ lighttpd built: ${LIGHTTPD_BIN} ($(du -h "${LIGHTTPD_BIN}" | cut -f1))"
fi

# ── Download static BusyBox ────────────────────────────────────────────────

echo ""
echo "Downloading static BusyBox..."

BUSYBOX_URL="https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"
BUSYBOX_BIN="${SCRIPT_DIR}/busybox"

if [[ ! -f "${BUSYBOX_BIN}" ]]; then
    curl -fSL -o "${BUSYBOX_BIN}" "${BUSYBOX_URL}"
    chmod +x "${BUSYBOX_BIN}"
fi
echo "  ✓ ${BUSYBOX_BIN}"

# ── Create staging directory ────────────────────────────────────────────────

echo ""
echo "Creating rootfs staging directory..."
rm -rf "${ROOTFS_DIR}"
mkdir -p "${ROOTFS_DIR}"/{bin,sbin,lib64,lib,etc/lighttpd,proc,sys,dev,tmp/docroot,var/run,var/log,var/tmp,usr/bin,usr/sbin,usr/lib/x86_64-linux-gnu}

# ── Install lighttpd binary + gcov data ─────────────────────────────────────

cp "${LIGHTTPD_BIN}" "${ROOTFS_DIR}/bin/lighttpd"
chmod +x "${ROOTFS_DIR}/bin/lighttpd"
echo "  ✓ /bin/lighttpd installed"

# ── Install shared libraries (from Docker Ubuntu 22.04) ──────────────────────
# lighttpd is dynamically linked; we need libc and the dynamic linker.

echo ""
echo "Installing shared libraries from Ubuntu 22.04..."
LIB_STAGING=$(mktemp -d)
docker run --rm -v "${LIB_STAGING}:/out" ubuntu:22.04 bash -c "
    cp /lib64/ld-linux-x86-64.so.2 /out/ 2>/dev/null || true
    cp /usr/lib/x86_64-linux-gnu/libc.so.6 /out/ 2>/dev/null || \
        cp /lib/x86_64-linux-gnu/libc.so.6 /out/ 2>/dev/null || true
    cp /usr/lib/x86_64-linux-gnu/libgcov.so.1 /out/ 2>/dev/null || \
        cp /lib/x86_64-linux-gnu/libgcov.so.1 /out/ 2>/dev/null || true
    cp /usr/lib/x86_64-linux-gnu/libgcc_s.so.1 /out/ 2>/dev/null || \
        cp /lib/x86_64-linux-gnu/libgcc_s.so.1 /out/ 2>/dev/null || true
"
cp "${LIB_STAGING}/ld-linux-x86-64.so.2" "${ROOTFS_DIR}/lib64/" 2>/dev/null && \
    chmod +x "${ROOTFS_DIR}/lib64/ld-linux-x86-64.so.2"
cp "${LIB_STAGING}/libc.so.6" "${ROOTFS_DIR}/usr/lib/x86_64-linux-gnu/" 2>/dev/null
cp "${LIB_STAGING}/libgcov.so.1" "${ROOTFS_DIR}/usr/lib/x86_64-linux-gnu/" 2>/dev/null
cp "${LIB_STAGING}/libgcc_s.so.1" "${ROOTFS_DIR}/usr/lib/x86_64-linux-gnu/" 2>/dev/null
rm -rf "${LIB_STAGING}"
echo "  ✓ Shared libraries installed (libc, ld-linux, libgcov, libgcc_s)"

# Copy .gcno files (needed for lcov --capture later)
GCNO_COUNT=0
while IFS= read -r -d '' gcno; do
    DEST_DIR="${ROOTFS_DIR}$(dirname "${gcno#"${BUILD_DIR}"}")"
    mkdir -p "${DEST_DIR}"
    cp "${gcno}" "${DEST_DIR}/"
    GCNO_COUNT=$((GCNO_COUNT + 1))
done < <(find "${BUILD_DIR}/src" -name "*.gcno" -print0 2>/dev/null || true)
echo "  ✓ ${GCNO_COUNT} .gcno files copied (for future coverage extraction)"

# Make gcov build dirs writable so .gcda can be written at runtime
find "${ROOTFS_DIR}" -type d -exec chmod 777 {} \; 2>/dev/null || true

# ── Install BusyBox + symlinks ──────────────────────────────────────────────

cp "${BUSYBOX_BIN}" "${ROOTFS_DIR}/bin/busybox"
chmod +x "${ROOTFS_DIR}/bin/busybox"

for cmd in sh mount umount ip ln ls cat echo mkdir mknod sleep poweroff reboot cp mv rm; do
    ln -s busybox "${ROOTFS_DIR}/bin/${cmd}"
done
echo "  ✓ BusyBox installed with symlinks"

# ── Create lighttpd config ──────────────────────────────────────────────────

cat > "${ROOTFS_DIR}/etc/lighttpd/lighttpd.conf" << 'CONF_EOF'
# lighttpd Firecracker VM config — bind 0.0.0.0:9000, foreground mode
# NOTE: compat-module-load is disabled because we don't ship .so modules.
#       lighttpd was built with --enable-static; modules are .a archives,
#       but the runtime still dlopen()s unless we explicitly opt out.

server.bind          = "0.0.0.0"
server.port          = 9000

# Disable auto-loading of mod_indexfile / mod_dirlisting / mod_staticfile
server.compat-module-load = "disable"
server.modules       = ()

server.max-worker    = 1
server.max-connections = 64
server.max-fds       = 128

# Aggressive timeouts for fast crash detection
server.max-read-idle  = 5
server.max-write-idle = 5
server.max-keep-alive-idle = 2
server.max-keep-alive-requests = 10

# Logging
server.errorlog      = "/dev/stderr"
accesslog.filename   = ""

# Document root
server.document-root = "/tmp/docroot"

# MIME types (minimal)
mimetype.assign = (
    ".html" => "text/html",
    ".txt"  => "text/plain",
    ""      => "application/octet-stream",
)

server.upload-dirs   = ( "/tmp" )
CONF_EOF

echo "  ✓ /etc/lighttpd/lighttpd.conf created"

# ── Create minimal document root ────────────────────────────────────────────

echo "ok" > "${ROOTFS_DIR}/tmp/docroot/index.html"
echo "  ✓ /tmp/docroot/index.html created"

# ── Create /init ────────────────────────────────────────────────────────────

cat > "${ROOTFS_DIR}/init" << 'INIT_EOF'
#!/bin/sh
# /init — Firecracker MicroVM bootstrap for lighttpd fuzzing target
# Handles graceful degradation when network is unavailable.

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null   # may already be mounted by kernel
mount -t tmpfs tmpfs /tmp

mkdir -p /tmp/docroot /var/log /var/run /var/tmp

# Network setup — skip if no virtio-net (e.g. no TAP on host)
ip link set lo up 2>/dev/null
if ip link show eth0 >/dev/null 2>&1; then
    ip addr add 172.16.0.2/24 dev eth0
    ip link set eth0 up
    ip route add default via 172.16.0.1
    echo "LIFA-Fuzz Firecracker — lighttpd 1.4.55 on 172.16.0.2:9000"
else
    echo "LIFA-Fuzz Firecracker — lighttpd 1.4.55 (no network)"
fi

# Launch lighttpd in foreground (-D). If it crashes, VM exits.
exec /bin/lighttpd -D -f /etc/lighttpd/lighttpd.conf
INIT_EOF

chmod +x "${ROOTFS_DIR}/init"
echo "  ✓ /init created"

# ── Create minimal /etc files ───────────────────────────────────────────────

echo "root:x:0:0:root:/root:/bin/sh" > "${ROOTFS_DIR}/etc/passwd"
echo "root:x:0:" > "${ROOTFS_DIR}/etc/group"
echo "passwd: files" > "${ROOTFS_DIR}/etc/nsswitch.conf"
echo "group:  files" >> "${ROOTFS_DIR}/etc/nsswitch.conf"
echo "lifa-lighttpd" > "${ROOTFS_DIR}/etc/hostname"
echo "  ✓ /etc files created"

# ── Build ext4 image ────────────────────────────────────────────────────────

echo ""
echo "Building ext4 image (${ROOTFS_SIZE_MB}MB)..."

dd if=/dev/zero of="${OUTPUT}" bs=1M count="${ROOTFS_SIZE_MB}" status=none
mkfs.ext4 -F -q "${OUTPUT}"

# Copy files using debugfs — robust approach with deduplicated mkdirs,
# explicit symlinks, and executable permissions.
DEBUGFS_SCRIPT=$(mktemp)
echo "" > "${DEBUGFS_SCRIPT}"

# 1. Collect unique directories and create them
declare -A SEEN_DIRS
while IFS= read -r -d '' f; do
    REL_PATH="${f#${ROOTFS_DIR}}"
    DIR_NAME=$(dirname "${REL_PATH}")
    if [[ "${DIR_NAME}" != "/" && "${DIR_NAME}" != "" && -z "${SEEN_DIRS[${DIR_NAME}]:-}" ]]; then
        echo "mkdir ${DIR_NAME}" >> "${DEBUGFS_SCRIPT}"
        SEEN_DIRS["${DIR_NAME}"]=1
    fi
done < <(find "${ROOTFS_DIR}" -type f -print0)

# 2. Write all regular files
while IFS= read -r -d '' f; do
    REL_PATH="${f#${ROOTFS_DIR}}"
    echo "write ${f} ${REL_PATH}" >> "${DEBUGFS_SCRIPT}"
done < <(find "${ROOTFS_DIR}" -type f -print0)

# 3. Set executable permissions on critical binaries
for bin in init bin/busybox bin/lighttpd lib64/ld-linux-x86-64.so.2; do
    echo "set_inode_field /${bin} mode 0100755" >> "${DEBUGFS_SCRIPT}"
done
echo "set_inode_field /usr/lib/x86_64-linux-gnu/libc.so.6 mode 0100755" >> "${DEBUGFS_SCRIPT}"
echo "set_inode_field /usr/lib/x86_64-linux-gnu/libgcc_s.so.1 mode 0100755" >> "${DEBUGFS_SCRIPT}"

# 4. Create BusyBox symlinks (debugfs syntax: symlink <link_path> <target>)
for cmd in sh mount umount ip ln ls cat echo mkdir mknod sleep poweroff reboot cp mv rm; do
    echo "symlink /bin/${cmd} busybox" >> "${DEBUGFS_SCRIPT}"
done

if command -v debugfs &>/dev/null; then
    debugfs -w -f "${DEBUGFS_SCRIPT}" "${OUTPUT}" 2>&1 | grep -i "error" | head -5 || true
    rm -f "${DEBUGFS_SCRIPT}"
    echo "  ✓ Files, symlinks, and permissions written via debugfs"
else
    rm -f "${DEBUGFS_SCRIPT}"
    echo "  ⚠ debugfs not found — trying sudo mount..."
    MOUNT_POINT=$(mktemp -d)
    sudo mount -o loop "${OUTPUT}" "${MOUNT_POINT}"
    sudo cp -a "${ROOTFS_DIR}"/* "${MOUNT_POINT}/"
    sudo umount "${MOUNT_POINT}"
    rmdir "${MOUNT_POINT}"
fi

echo ""
echo "✓ RootFS built: ${OUTPUT}"
echo "  Size: $(du -h "${OUTPUT}" | cut -f1)"
echo "  Files: $(find "${ROOTFS_DIR}" -type f | wc -l)"

# ── Cleanup staging ─────────────────────────────────────────────────────────
# NOTE: staging is kept for faster rebuilds. Use --force to rebuild from scratch.
# The rootfs image is the final artifact; staging is reusable.

echo ""
echo "============================================================"
