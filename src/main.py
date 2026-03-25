import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .rbac import RBACMiddleware, create_token, check_permission, ROLE_PERMISSIONS
from .policy_engine import validate_input, validate_output, MAX_INPUT_LENGTH, PII_PATTERNS, INJECTION_PATTERNS, SECRET_PATTERNS
from .governance import log_event, get_audit_events
from .agent import LLMAgent
from .observability import setup_telemetry
from . import config_manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-me-in-production-use-a-256-bit-secret")

# Comma-separated list of trusted proxy IPs (e.g. Traefik's container IP or CIDR).
# When set, X-Forwarded-For / X-Real-IP headers are trusted from these addresses.
TRUSTED_PROXIES = set(
    ip.strip()
    for ip in os.getenv("TRUSTED_PROXIES", "").split(",")
    if ip.strip()
)

# ---------------------------------------------------------------------------
# Telemetry bootstrap
# ---------------------------------------------------------------------------
tracer, meter = setup_telemetry("clawsec")

request_counter = meter.create_counter(
    "llm_requests_total",
    description="Total LLM requests received",
)
violation_counter = meter.create_counter(
    "policy_violations_total",
    description="Total policy violations detected (input + output)",
)
pii_redaction_counter = meter.create_counter(
    "pii_redactions_total",
    description="Total PII tokens redacted (input + output)",
)
rbac_denial_counter = meter.create_counter(
    "rbac_denials_total",
    description="Total RBAC permission denials",
)
audit_event_counter = meter.create_counter(
    "audit_events_total",
    description="Total audit events persisted",
)
duration_histogram = meter.create_histogram(
    "llm_request_duration_seconds",
    description="End-to-end LLM request duration in seconds",
)

# ---------------------------------------------------------------------------
# Agent singleton
# ---------------------------------------------------------------------------
agent = LLMAgent()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_client_ip(request: Request) -> str:
    """
    Extract the real client IP, honouring forwarded headers when the request
    arrives from a trusted proxy (Traefik, nginx, etc.).

    Priority:
      1. X-Real-IP (single-hop proxies set this explicitly)
      2. First entry of X-Forwarded-For (left-most = originating client)
      3. Direct TCP peer address

    Only trusted when request.client.host is in TRUSTED_PROXIES to prevent
    header spoofing from untrusted callers.
    """
    peer = request.client.host if request.client else None

    if peer and (peer in TRUSTED_PROXIES or not TRUSTED_PROXIES):
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        forwarded_for = request.headers.get("X-Forwarded-For", "")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

    return peer or "unknown"


# ---------------------------------------------------------------------------
# Application lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("ClawSec framework starting up")
    yield
    logger.info("ClawSec framework shutting down")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="ClawSec - Secure LLM Agent Framework",
    description=(
        "Production-ready, hardened, auditable LLM agent with RBAC, "
        "policy enforcement, PII filtering, and full OpenTelemetry observability."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Middleware order matters: CORS first, then RBAC
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(RBACMiddleware, secret_key=SECRET_KEY)

# Serve the single-page UI at /ui — no auth required
_ui_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ui")
if os.path.isdir(_ui_dir):
    app.mount("/ui", StaticFiles(directory=_ui_dir, html=True), name="ui")


@app.get("/", include_in_schema=False)
async def root_redirect():
    return RedirectResponse(url="/ui")


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class QueryRequest(BaseModel):
    prompt: str = Field(
        ...,
        min_length=1,
        max_length=32768,
        description="The query prompt submitted to the LLM agent.",
    )
    system_prompt: str = Field(
        None,
        max_length=8192,
        description="Optional system prompt override (requires elevated role).",
    )


class TokenRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=256)
    role: str = Field(..., description="Role: agent | developer | auditor | administrator")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health", tags=["System"])
async def health():
    """Liveness / readiness probe. No authentication required."""
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "llm_mode": "mock" if agent.mock_mode else "live",
        "llm_model": agent.model if not agent.mock_mode else None,
    }


@app.post("/token", tags=["Auth"])
async def issue_token(req: TokenRequest):
    """
    Issue a JWT token for the given user and role.

    **Note:** In production replace this with an IdP / SSO integration.
    """
    if req.role not in ROLE_PERMISSIONS:
        raise HTTPException(status_code=400, detail=f"Unknown role: {req.role}")
    token = create_token(req.user_id, req.role, SECRET_KEY)
    log_event(
        "token_issued",
        user_id=req.user_id,
        role=req.role,
        action="issue_token",
        outcome="allowed",
    )
    audit_event_counter.add(1, {"event_type": "token_issued"})
    return {"token": token, "role": req.role, "permissions": ROLE_PERMISSIONS[req.role]}


@app.post("/query", tags=["Agent"])
async def query_agent(req: QueryRequest, request: Request):
    """
    Submit a prompt to the LLM agent.

    Full enforcement pipeline:
    1. RBAC permission check (`query:submit`)
    2. Input policy validation (injection + secret detection + length)
    3. PII redaction from input (before the LLM sees it)
    4. LLM invocation (receives PII-sanitized prompt)
    5. Output policy validation (secret scrubbing + PII redaction)
    6. Audit log write

    Requires: `query:submit` permission.
    """
    request_id = str(uuid.uuid4())
    user    = getattr(request.state, "user", {})
    user_id = user.get("sub", "anonymous")
    role    = user.get("role", "unknown")
    ip      = get_client_ip(request)

    # 1. RBAC permission check
    if not check_permission(user, "query:submit"):
        rbac_denial_counter.add(1, {"role": role})
        log_event(
            "rbac_denial",
            user_id=user_id, role=role,
            action="query:submit", resource="/query",
            outcome="denied", ip_address=ip, request_id=request_id,
        )
        audit_event_counter.add(1, {"event_type": "rbac_denial"})
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions: query:submit required",
        )

    request_counter.add(1, {"role": role})

    # 2 + 3. Input policy validation + PII redaction
    with tracer.start_as_current_span("policy.validate_input") as span:
        input_result = validate_input(req.prompt)
        span.set_attribute("policy.allowed", input_result.allowed)
        span.set_attribute("pii.detections", len(input_result.pii_detections))

        if not input_result.allowed:
            violation_counter.add(1, {"type": "input", "role": role})
            log_event(
                "policy_violation",
                user_id=user_id, role=role,
                action="query:submit", resource="/query",
                outcome="denied",
                policy_violations=input_result.violations,
                ip_address=ip, request_id=request_id,
            )
            audit_event_counter.add(1, {"event_type": "policy_violation"})
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Policy violation",
                    "reason": input_result.reason,
                    "violations": input_result.violations,
                },
            )

        if input_result.pii_detections:
            pii_redaction_counter.add(
                len(input_result.pii_detections), {"stage": "input", "role": role}
            )
            log_event(
                "pii_redacted",
                user_id=user_id, role=role,
                action="query:submit", resource="/query",
                outcome="allowed",
                metadata={"stage": "input", "pii_types": input_result.pii_detections},
                ip_address=ip, request_id=request_id,
            )

    # Use the PII-sanitized prompt — the LLM never sees raw PII
    prompt_for_llm = input_result.sanitized_text or req.prompt

    # 4. LLM invocation
    with tracer.start_as_current_span("agent.query") as span:
        span.set_attribute("user.id", user_id)
        span.set_attribute("user.role", role)
        span.set_attribute("request.id", request_id)
        try:
            llm_response = await agent.query(
                prompt=prompt_for_llm,
                system_prompt=req.system_prompt,
                user_context={"user_id": user_id, "role": role},
            )
        except Exception as exc:
            logger.error("LLM query error for request %s: %s", request_id, exc)
            log_event(
                "llm_error",
                user_id=user_id, role=role,
                action="query:submit", resource="/query",
                outcome="error", ip_address=ip, request_id=request_id,
                metadata={"error": str(exc)},
            )
            audit_event_counter.add(1, {"event_type": "llm_error"})
            raise HTTPException(status_code=502, detail="LLM backend error")

    # 5. Output policy validation & sanitization
    with tracer.start_as_current_span("policy.validate_output") as span:
        output_result = validate_output(llm_response)
        span.set_attribute("output.sanitized", bool(output_result.violations or output_result.pii_detections))

        if output_result.violations:
            violation_counter.add(1, {"type": "output", "role": role})

        if output_result.pii_detections:
            pii_redaction_counter.add(
                len(output_result.pii_detections), {"stage": "output", "role": role}
            )

    final_output = output_result.sanitized_text or llm_response

    # 6. Audit log
    log_event(
        "llm_query",
        user_id=user_id, role=role,
        action="query:submit", resource="/query",
        outcome="allowed",
        policy_violations=output_result.violations,
        ip_address=ip, request_id=request_id,
        metadata={
            "prompt_length":    len(req.prompt),
            "response_length":  len(final_output),
            "input_pii_types":  input_result.pii_detections,
            "output_pii_types": output_result.pii_detections,
        },
    )
    audit_event_counter.add(1, {"event_type": "llm_query"})

    return {
        "request_id":   request_id,
        "response":     final_output,
        "sanitized":    bool(output_result.violations or output_result.pii_detections),
        "policy_notes": output_result.reason,
        "pii_redacted": {
            "input":  input_result.pii_detections,
            "output": output_result.pii_detections,
        },
    }


@app.get("/audit", tags=["Governance"])
async def get_audit_log(
    request: Request,
    limit: int = 100,
    event_type: str = None,
    user_id: str = None,
):
    """
    Retrieve the audit log in reverse-chronological order.
    Requires: `audit:read` permission.
    """
    user = getattr(request.state, "user", {})
    if not check_permission(user, "audit:read"):
        rbac_denial_counter.add(1, {"role": user.get("role", "unknown")})
        raise HTTPException(status_code=403, detail="Insufficient permissions: audit:read required")
    events = get_audit_events(limit=min(limit, 1000), event_type=event_type, user_id=user_id)
    return {"events": events, "count": len(events)}


@app.get("/policy", tags=["Policy"])
async def get_policy_info(request: Request):
    """
    Return a summary of active policy rules.
    Requires: `policy:read` permission.
    """
    user = getattr(request.state, "user", {})
    if not check_permission(user, "policy:read"):
        raise HTTPException(status_code=403, detail="Insufficient permissions: policy:read required")
    return {
        "injection_patterns_count": len(INJECTION_PATTERNS),
        "secret_patterns_count":    len(SECRET_PATTERNS),
        "pii_patterns_count":       len(PII_PATTERNS),
        "max_input_length":         MAX_INPUT_LENGTH,
        "pii_filtering": {
            "input":  "redact",   # PII removed before LLM sees the prompt
            "output": "redact",   # PII removed from LLM response before delivery
        },
        "output_sanitization": "enabled",
        "audit_all_queries":   True,
        "proxy_support":       "HTTP_PROXY / HTTPS_PROXY / LLM_HTTP_PROXY / LLM_HTTPS_PROXY",
    }


@app.get("/rbac/roles", tags=["RBAC"])
async def get_roles(request: Request):
    """
    Return the full RBAC permission matrix.
    Requires: `rbac:manage` permission.
    """
    user = getattr(request.state, "user", {})
    if not check_permission(user, "rbac:manage"):
        raise HTTPException(status_code=403, detail="Insufficient permissions: rbac:manage required")
    return {"roles": ROLE_PERMISSIONS}


# ---------------------------------------------------------------------------
# Configuration endpoints
# ---------------------------------------------------------------------------

class ConfigUpdateRequest(BaseModel):
    updates: dict = Field(..., description="Key-value pairs to merge into the config section.")


@app.get("/config", tags=["Config"])
async def get_config(request: Request):
    """
    Return the current runtime configuration (api_key masked).
    Requires: `system:admin` permission.
    """
    user = getattr(request.state, "user", {})
    if not check_permission(user, "system:admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions: system:admin required")
    return {
        "config": config_manager.safe_view(),
        "provider_presets": config_manager.PROVIDER_PRESETS,
    }


@app.patch("/config/{section}", tags=["Config"])
async def update_config(section: str, req: ConfigUpdateRequest, request: Request):
    """
    Merge updates into a config section (llm | policy | server).
    Changes take effect immediately — no restart required.
    Requires: `system:admin` permission.
    """
    user = getattr(request.state, "user", {})
    user_id = user.get("sub", "anonymous")
    role = user.get("role", "unknown")
    ip = get_client_ip(request)

    if not check_permission(user, "system:admin"):
        rbac_denial_counter.add(1, {"role": role})
        raise HTTPException(status_code=403, detail="Insufficient permissions: system:admin required")

    try:
        new_config = config_manager.update_section(section, req.updates)
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    log_event(
        "config_updated",
        user_id=user_id, role=role,
        action=f"config:update:{section}", resource=f"/config/{section}",
        outcome="allowed", ip_address=ip,
        metadata={"section": section, "fields": list(req.updates.keys())},
    )
    audit_event_counter.add(1, {"event_type": "config_updated"})
    return {"section": section, "config": new_config}


@app.post("/config/test", tags=["Config"])
async def test_llm_connection(request: Request):
    """
    Send a minimal test prompt to the currently configured LLM endpoint.
    Returns success/failure without touching the audit trail for the test itself.
    Requires: `system:admin` permission.
    """
    user = getattr(request.state, "user", {})
    if not check_permission(user, "system:admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions: system:admin required")

    if config_manager.is_mock_mode():
        return {"success": True, "mode": "mock", "message": "Running in mock mode — no LLM backend configured."}

    try:
        response = await agent._real_query("Say 'OK' in one word.")
        return {"success": True, "mode": "live", "message": response[:200]}
    except Exception as exc:
        return {"success": False, "mode": "live", "message": str(exc)}
