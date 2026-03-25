# ===========================================================================
# Stage 1: Build — install Python dependencies into /install
# ===========================================================================
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build-time system dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ===========================================================================
# Stage 2: Runtime — minimal attack surface, non-root user
# ===========================================================================
FROM python:3.12-slim AS runtime

# Security: create a dedicated non-root user/group
RUN groupadd -r clawsec && \
    useradd -r -g clawsec -d /app -s /sbin/nologin clawsec

# Install only the runtime system libraries we need
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Pull installed Python packages from the builder stage
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy only the application source — no tests, no scripts
COPY src/ ./src/
COPY config/ ./config/
COPY ui/ ./ui/

# Lock down ownership before dropping privileges
RUN chown -R clawsec:clawsec /app

# Drop to non-root
USER clawsec

# Expose API port and Prometheus metrics port
EXPOSE 8000 9090

# Liveness / readiness probe used by Docker and Kubernetes
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Use exec form (no shell) for reliable signal handling
ENTRYPOINT ["python", "-m", "uvicorn", "src.main:app", \
            "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
