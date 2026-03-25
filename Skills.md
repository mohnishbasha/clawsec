# ClawSec Skills

This document describes the security capabilities and skills built into the ClawSec framework.

## 1. Role-Based Access Control (RBAC)

**Module:** `src/rbac.py`

ClawSec enforces a four-tier role model using signed JWTs. Every protected endpoint requires a valid token, and permissions are checked per-route.

| Role | Permissions |
|------|-------------|
| `agent` | `query:submit` |
| `developer` | `query:submit`, `policy:read`, `config:write` |
| `auditor` | `audit:read`, `policy:read`, `metrics:read` |
| `administrator` | All permissions including `rbac:manage` |

**How it works:**
- Tokens are issued via `POST /token` with a `user_id` and `role`.
- Tokens are signed with HS256 and expire after 1 hour.
- `RBACMiddleware` intercepts every request, verifies the signature, checks expiry, and validates that the caller's role grants the required permission for the endpoint.
- Denied requests are logged as `rbac_denial` events in the audit trail.

**Production guidance:** Replace the `/token` endpoint with your IdP (Okta, Azure AD, Auth0) and enforce MFA for the `administrator` role.

---

## 2. Prompt Injection Detection

**Module:** `src/policy_engine.py` — `validate_input()`

Incoming prompts are scanned against 13 regex patterns before being forwarded to the LLM. Matches result in an HTTP 400 response; the query never reaches the model.

**Detected patterns include:**
- Instruction override: `ignore previous instructions`, `disregard all prior`, `forget your instructions`
- Identity hijacking: `you are now`, `act as`, `pretend you are`, `roleplay as`
- Jailbreak keywords: `jailbreak`, `DAN mode`, `developer mode`, `unrestricted mode`
- System tag injection: `<system>`, `[INST]`, `[SYS]`
- Safety bypass: `ignore your safety`, `bypass content filter`, `override your guidelines`

All blocked attempts are recorded in the audit trail as `policy_violation` events.

---

## 3. Secret Exfiltration Prevention

**Module:** `src/policy_engine.py` — `validate_input()` and `validate_output()`

ClawSec blocks secrets from entering the LLM and redacts any that appear in the output.

**Detected credential patterns:**
- Generic: `password=`, `api_key=`, `secret_key=`, `access_token=`, `auth_token=`
- OpenAI keys: `sk-[A-Za-z0-9]{48}`
- AWS access keys: `AKIA[0-9A-Z]{16}`
- GitHub tokens: `ghp_[A-Za-z0-9]{36}`, `github_pat_...`
- PEM private keys: `-----BEGIN ... PRIVATE KEY-----`
- High-entropy base64 blobs (40+ chars)

**On input:** request is rejected with HTTP 400.
**On output:** matched values are replaced with `[REDACTED]` before the response is returned to the caller.

---

## 4. PII Redaction

**Module:** `src/policy_engine.py` — `validate_output()`

All LLM responses are scrubbed for personally identifiable information before delivery. Matched values are replaced with `[REDACTED]`.

**Covered PII categories (14+ patterns):**

| Category | Examples |
|----------|---------|
| Identity | US SSN (`XXX-XX-XXXX`), passport numbers, driver's license |
| Financial | Credit cards (Visa, MC, Amex, Discover), IBAN, bank account numbers |
| Contact | Email addresses, US phone numbers, UK phone numbers |
| Medical | Medical Record Numbers (MRN), NHS numbers |
| Network | IPv4 addresses, IPv6 addresses |
| Temporal | Date of birth (contextual patterns) |

---

## 5. Immutable Audit Trail

**Module:** `src/governance.py`

Every security-relevant event is written to an append-only audit log backed by SQLite (development) or PostgreSQL (production). Records cannot be modified after creation.

**Event types:**

| Event | Trigger |
|-------|---------|
| `token_issued` | JWT issued via `/token` |
| `llm_query` | Successful LLM query |
| `policy_violation` | Input blocked by injection or secret detection |
| `rbac_denial` | Request rejected due to insufficient permissions |
| `llm_error` | Upstream LLM call failed |

**Each record captures:**
- Timestamp, request ID (UUID4), IP address
- User ID, role, action, resource
- Outcome (`allowed` / `denied`)
- Policy violations (which patterns matched)
- Metadata (model, token counts, response time)

Prompt content is never stored — only lengths and outcomes.

**Access:** `GET /audit` requires the `audit:read` permission (auditor or administrator role). Supports `?limit=` and `?event_type=` query parameters.

**Retention:** 365 days (configurable).

---

## 6. Observability & Metrics

**Module:** `src/observability.py`

ClawSec emits signals across all three observability pillars.

### Prometheus Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `llm_requests_total` | Counter | `role` | Total LLM queries |
| `policy_violations_total` | Counter | `type`, `role` | Blocked inputs by pattern type |
| `rbac_denials_total` | Counter | `role` | Access control rejections |
| `audit_events_total` | Counter | `event_type` | Audit events by type |
| `llm_request_duration_seconds` | Histogram | — | End-to-end latency |

### Distributed Tracing

OpenTelemetry traces (OTLP gRPC) are exported to the OTel Collector. Each request gets a unique `request_id` that appears in traces, logs, and the audit record for full correlation.

### Log Storage

Structured logs are shipped to VictoriaLogs (4-week retention) via the OTel Collector. Metrics are stored in VictoriaMetrics (3-month retention).

### Grafana Dashboard

A pre-built dashboard (`dashboards/grafana_dashboard.json`) is auto-provisioned with 5 panels: total requests, violations, RBAC denials, request rate over time, and violations/denials timeline.

---

## 7. LLM Provider Flexibility

**Module:** `src/agent.py`

ClawSec connects to any OpenAI-compatible endpoint. The provider is configured via environment variables and can be hot-reloaded without restarting the application.

**Supported providers:**
- OpenAI (`gpt-4o`, `gpt-4-turbo`, etc.)
- Groq (free tier, fast inference)
- Ollama (local, air-gapped, no API key required)
- Any OpenAI-compatible API (Azure OpenAI, Together AI, etc.)
- **Mock mode** — when `LLM_API_URL` is not set, responses are mocked; safe for testing and CI

Outbound proxy support is available via standard `HTTP_PROXY` / `HTTPS_PROXY` environment variables.

---

## 8. Dynamic Configuration

**Module:** `src/config_manager.py`

Policy rules, RBAC role definitions, and LLM settings can be updated at runtime. The config manager polls for file changes and reloads without requiring an application restart.

**Config files:**
- `config/policy_rules.yaml` — Add or update injection/secret/PII patterns
- `config/rbac_roles.yaml` — Modify role permissions
- LLM settings (`model`, `max_tokens`, `temperature`) — updated via environment variables

---

## 9. Container & Infrastructure Hardening

ClawSec ships with hardened runtime defaults for both Docker and Kubernetes.

**Docker:**
- Multi-stage build (build tools stripped from runtime image)
- Non-root user `clawsec` (UID 1000)
- Read-only root filesystem + `/tmp` tmpfs
- All Linux capabilities dropped (`cap_drop: ALL`)
- No privilege escalation (`no-new-privileges: true`)
- Traefik reverse proxy with rate limiting (100 req/min per IP) and security headers

**Kubernetes:**
- `securityContext`: non-root, read-only filesystem, `allowPrivilegeEscalation: false`
- Seccomp profile: `RuntimeDefault`
- `NetworkPolicy`: ingress restricted to ingress-nginx on port 8000 and monitoring namespace on port 9090
- Kubernetes RBAC: dedicated `ServiceAccount` with minimal permissions
- Secrets managed via `kubectl create secret` (not baked into manifests)
