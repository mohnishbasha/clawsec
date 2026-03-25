#!/usr/bin/env bash
# stop.sh — Gracefully stop the ClawSec stack.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

echo "Stopping ClawSec..."
docker compose down
echo "ClawSec stopped."
