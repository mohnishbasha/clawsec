#!/usr/bin/env bash
# start.sh — Build and start the full ClawSec observability stack.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

echo "================================================"
echo "  ClawSec — Secure LLM Agent Framework"
echo "================================================"
echo ""

# Generate .env if it doesn't already exist
if [ ! -f .env ]; then
    echo "WARNING: No .env file found. Generating one with random secrets."
    echo "         Review and update before going to production."
    echo ""

    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    GRAFANA_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")

    cat > .env <<EOF
# -------------------------------------------------------
# ClawSec environment — auto-generated on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# CHANGE ALL VALUES before deploying to production.
# -------------------------------------------------------

# Required: 256-bit secret for JWT signing
JWT_SECRET_KEY=${JWT_SECRET}

# Grafana admin password
GRAFANA_PASSWORD=${GRAFANA_PASS}

# LLM backend (leave blank to use built-in mock mode)
LLM_API_URL=
LLM_API_KEY=
LLM_MODEL=gpt-4

# CORS allowed origins (comma-separated)
ALLOWED_ORIGINS=http://localhost:3000
EOF
    echo ".env created. JWT_SECRET_KEY and GRAFANA_PASSWORD have been randomly generated."
    echo ""
fi

echo "Building and starting containers..."
docker compose up -d --build

echo ""
echo "================================================"
echo "  ClawSec started successfully!"
echo ""
echo "  API endpoint:  http://localhost:8000"
echo "  API docs:      http://localhost:8000/docs"
echo "  Prometheus:    http://localhost:9091"
echo "  Grafana:       http://localhost:3000"
echo "    (password in .env -> GRAFANA_PASSWORD)"
echo "================================================"
echo ""
echo "Quick smoke-test:"
echo "  curl http://localhost:8000/health"
echo ""
