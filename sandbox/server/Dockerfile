# =============================================================================
# LIFA-Fuzz Target Server — Dockerfile
# =============================================================================
# A minimal Python TCP server that echoes received packets.
# Replace this with your actual proprietary server binary in production.

FROM python:3.11-slim

WORKDIR /app

COPY server.py .

EXPOSE 9000

CMD ["python", "server.py"]
