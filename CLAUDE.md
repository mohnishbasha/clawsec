# CLAUDE.md

This file provides guidance for Claude Code when working in this repository.

## Project Overview

ClawSec is a hardened LLM agent framework for secure enterprise AI deployment. It wraps LLM calls in a security pipeline: RBAC (JWT), prompt injection detection, secret blocking, PII redaction, and an immutable audit trail.

## Common Commands

```bash
# Start the full Docker Compose stack (generates .env on first run)
./scripts/start.sh

# Stop the stack
./scripts/stop.sh

# Run all tests
./scripts/test.sh

# Run tests directly with pytest
python -m pytest tests/ -v

# Run a specific test module
python -m pytest tests/test_policy_engine.py -v
python -m pytest tests/test_rbac.py -v
python -m pytest tests/test_governance.py -v
python -m pytest tests/test_integration.py -v

# Run the interactive security demo
./scripts/sample_queries.sh

# Install Python dependencies
pip install -r requirements.txt
```

## Architecture

```
HTTP Request
  → RBACMiddleware (verify JWT, check permissions)
  → validate_input() — block prompt injection & secrets
  → LLMAgent.query() — OpenAI-compatible REST call (or mock)
  → validate_output() — redact PII & secrets
  → log_event() — immutable audit trail
  → Prometheus metrics + OTel traces
```

## Key Source Files

| File | Responsibility |
|------|---------------|
| `src/main.py` | FastAPI app, route handlers, middleware wiring |
| `src/rbac.py` | JWT creation/verification, 4-role permission matrix, `RBACMiddleware` |
| `src/policy_engine.py` | Input/output validation — injection, secret, and PII regex patterns |
| `src/governance.py` | SQLAlchemy audit trail ORM and `log_event()` |
| `src/agent.py` | LLM agent wrapper (OpenAI-compatible + mock mode) |
| `src/observability.py` | OpenTelemetry tracing + Prometheus metrics setup |
| `src/config_manager.py` | Dynamic config with hot-reload (no restart needed) |

## API Endpoints

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| GET | `/health` | No | — | Liveness check |
| POST | `/token` | No | — | Issue JWT (`user_id` + `role`) |
| POST | `/query` | Yes | `query:submit` | Submit prompt to LLM |
| GET | `/audit` | Yes | `audit:read` | Audit log (`?limit=` + `?event_type=`) |
| GET | `/policy` | Yes | `policy:read` | Policy rules summary |
| GET | `/rbac/roles` | Yes | `rbac:manage` | Role → permissions matrix |

Swagger UI is available at `http://localhost:8000/docs` when running.

## RBAC Roles

| Role | Capabilities |
|------|-------------|
| `agent` | Submit queries, read outputs |
| `developer` | Agent + read policy config, configure models |
| `auditor` | Read-only audit/policy/metrics (cannot submit queries) |
| `administrator` | Full access |

## Security Pipeline Layers

1. **RBAC** — JWT (HS256, 1-hour expiry) enforced on all protected routes
2. **Input validation** — 13 prompt injection patterns + 10 secret exfiltration patterns (returns HTTP 400)
3. **Output scrubbing** — 14+ PII patterns (SSN, cards, emails, phones, IBANs, etc.) redacted before delivery
4. **Audit trail** — Every event written to SQLite/PostgreSQL; no prompt content stored, only lengths and outcomes

## Configuration

Config files live in `config/`:
- `rbac_roles.yaml` — Role definitions and restrictions
- `policy_rules.yaml` — Injection/secret/PII pattern catalogue
- `otel_collector.yaml` — OpenTelemetry Collector pipeline
- `prometheus.yaml` — Prometheus scrape config

Config changes take effect immediately via hot-reload (`config_manager.py`); no app restart required.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `JWT_SECRET_KEY` | Yes | (unsafe default) | 256-bit HMAC-SHA256 signing key |
| `LLM_API_URL` | No | (mock mode) | OpenAI-compatible endpoint |
| `LLM_API_KEY` | No | (mock mode) | LLM provider API key |
| `LLM_MODEL` | No | `gpt-4o` | Model name |
| `DATABASE_URL` | No | SQLite file | SQLAlchemy connection string |
| `OTLP_ENDPOINT` | No | `http://otel-collector:4317` | OTel Collector gRPC endpoint |
| `ALLOWED_ORIGINS` | No | `http://localhost:3000` | CORS allowed origins |

Copy `.env.example` to `.env` and populate before starting. `./scripts/start.sh` generates safe random values automatically on first run.

## Testing

The test suite has 60+ cases covering:
- All four RBAC roles and permission boundaries
- Prompt injection blocking (all 13 patterns)
- Secret exfiltration blocking
- Jailbreak attempt blocking
- Unauthenticated and under-privileged access (403)
- Audit log access controls
- Token issuance and validation

Tests use an in-memory SQLite database and mock LLM responses — no external services required.

## Docker Compose Stack

Services started by `./scripts/start.sh`:

| Service | URL |
|---------|-----|
| ClawSec API | http://localhost:8000 |
| Swagger UI | http://localhost:8000/docs |
| Prometheus | http://localhost:9091 |
| Grafana | http://localhost:3000 |
| VictoriaMetrics | http://localhost:8428 |
| VictoriaLogs | http://localhost:9428 |

## Kubernetes Deployment

Manifests are in `kubernetes/`. Apply in order:

```bash
kubectl apply -f kubernetes/namespace.yaml
kubectl apply -f kubernetes/

kubectl create secret generic clawsec-secrets \
  --namespace=clawsec \
  --from-literal=jwt-secret-key="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
  --from-literal=llm-api-key="sk-..."
```

## Development Notes

- The app runs in **mock mode** when `LLM_API_URL` is not set — safe for local development and testing without any LLM provider credentials.
- Prometheus metrics are exported at `http://localhost:8000/metrics` (scraped by the Prometheus container).
- The Grafana dashboard is auto-provisioned from `dashboards/grafana_dashboard.json`.
- The single-page UI lives in `ui/index.html` and is served at `http://localhost:8000/ui`.
