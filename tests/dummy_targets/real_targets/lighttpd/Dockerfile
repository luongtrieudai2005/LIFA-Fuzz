# =============================================================================
# lighttpd Docker image with gcov instrumentation for LIFA-Fuzz evaluation.
# =============================================================================
# Build:
#   docker build -t lifa-lighttpd-cov tests/dummy_targets/real_targets/lighttpd/
#
# Run (standalone):
#   docker run --rm -p 8080:8080 lifa-lighttpd-cov
#
# Used by evaluation_runner.py --target lighttpd
# =============================================================================

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies + lcov for in-container coverage capture
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        wget gcc make g++ ca-certificates lcov && \
    rm -rf /var/lib/apt/lists/*

# Build lighttpd with gcov
COPY prepare_lighttpd.sh /prepare.sh
RUN bash /prepare.sh

# Make gcov build dirs writable so .gcda files can be written at runtime
RUN find /tmp/lighttpd-1.4.55 -type d -exec chmod 777 {} \;

# Configuration — bind 0.0.0.0 (required inside Docker)
COPY lighttpd-docker.conf /etc/lighttpd/lighttpd.conf

# Document root with a minimal index page
RUN mkdir -p /tmp/lifa-lighttpd-docroot && \
    echo "ok" > /tmp/lifa-lighttpd-docroot/index.html

# Expose HTTP port
EXPOSE 8080

# Run as root (needed for gcov .gcda writes + stderr access in Docker)
CMD ["/tmp/lifa-lighttpd-install/sbin/lighttpd", "-D", "-f", "/etc/lighttpd/lighttpd.conf"]
