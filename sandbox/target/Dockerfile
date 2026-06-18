# =============================================================================
# LIFA-Fuzz Vulnerable Target Server — Dockerfile
# =============================================================================
# Compiles the deliberately vulnerable C server with stack protections
# disabled so the fuzzer can trigger real crashes.
#
# Build:
#   docker build -t lifa-target-server:latest .
#
# Run:
#   docker run -d -p 9000:9000 --name lifa-target-server lifa-target-server
# =============================================================================

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY vulnerable_server.c .

# Compile with stack protections DISABLED + ASAN for crash detection:
#   -O0               — no optimization (predictable stack layout)
#   -fno-stack-protector — remove stack canary
#   -z execstack       — mark stack as executable
#   -no-pie            — disable position-independent executable
#   -fsanitize=address — ASAN: catches buffer overflows at memcpy, prints
#                        report, aborts (abort_on_error baked in via source).
#                        Matches the Firecracker rootfs build for consistency.
RUN gcc -O0 -fno-stack-protector -z execstack -no-pie \
        -fsanitize=address -static-libasan -g \
        -o server vulnerable_server.c

EXPOSE 9000

CMD ["./server"]
