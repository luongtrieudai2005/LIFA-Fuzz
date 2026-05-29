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

# Compile with stack protections DISABLED for exploitability:
#   -O0               — no optimization (predictable stack layout)
#   -fno-stack-protector — remove stack canary
#   -z execstack       — mark stack as executable
#   -no-pie            — disable position-independent executable
RUN gcc -O0 -fno-stack-protector -z execstack -no-pie \
        -o server vulnerable_server.c

EXPOSE 9000

CMD ["./server"]
