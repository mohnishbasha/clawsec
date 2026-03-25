#!/usr/bin/env bash
# test.sh — Install dependencies and run the full ClawSec test suite.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

echo "================================================"
echo "  ClawSec — Test Suite"
echo "================================================"
echo ""

echo "Installing dependencies..."
pip install -r requirements.txt -q

echo ""
echo "--- Unit tests: policy engine ---"
python -m pytest tests/test_policy_engine.py -v

echo ""
echo "--- Unit tests: RBAC ---"
python -m pytest tests/test_rbac.py -v

echo ""
echo "--- Unit tests: governance / audit trail ---"
python -m pytest tests/test_governance.py -v

echo ""
echo "--- Integration tests ---"
python -m pytest tests/test_integration.py -v

echo ""
echo "================================================"
echo "  All tests passed!"
echo "================================================"
