# Sensors/templates/python-sensor/Dockerfile

# --- Stage 1: Builder ---
# Build from the repository root, like the Go sensors:
#   docker build -f Sensors/templates/python-sensor/Dockerfile .
FROM python:3.11-slim AS builder
WORKDIR /app

# The SDK comes from this repository (the source repository is private, so
# pip cannot fetch it from GitHub).
COPY SDKs/python-truesignal ./SDKs/python-truesignal

# Copy requirements (your custom libraries)
COPY Sensors/templates/python-sensor/requirements.txt .

# Install dependencies into a flat directory (--target /app/lib)
# This avoids virtualenv symlinks which can break inside Distroless
RUN pip install --no-cache-dir --target /app/lib ./SDKs/python-truesignal -r requirements.txt

# --- Stage 2: Distroless (Production) ---
FROM gcr.io/distroless/python3-debian12:nonroot
WORKDIR /app

# Copy the FLAT library folder. No symlinks, just code.
COPY --chown=65532:65532 --from=builder /app/lib /app/lib

# Copy the custom sensor script
COPY --chown=65532:65532 Sensors/templates/python-sensor/sensor.py .

# Tell Python to look in our lib folder first
ENV PYTHONPATH="/app/lib"
ENV PYTHONUNBUFFERED=1

USER 65532
# Distroless runs /usr/bin/python3 by default
CMD ["sensor.py"]