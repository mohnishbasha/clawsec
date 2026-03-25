import jwt
import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

ROLE_PERMISSIONS = {
    "agent": ["query:submit", "output:read"],
    "developer": ["query:submit", "output:read", "policy:read", "model:configure"],
    "auditor": ["audit:read", "policy:read", "output:read", "metrics:read"],
    "administrator": [
        "query:submit", "output:read", "policy:read", "policy:manage",
        "model:configure", "audit:read", "audit:delete",
        "rbac:manage", "system:admin", "metrics:read"
    ],
}

UNPROTECTED_PATHS = ["/health", "/metrics", "/docs", "/openapi.json", "/token", "/"]

# Path prefixes that bypass auth entirely (static assets, UI)
UNPROTECTED_PREFIXES = ["/ui"]


def create_token(user_id: str, role: str, secret_key: str, expiry_hours: int = 1) -> str:
    """
    Issue a signed JWT for the given user and role.

    Args:
        user_id: Unique identifier for the user (stored in the `sub` claim).
        role: One of the defined RBAC roles.
        secret_key: HMAC-SHA256 signing key.
        expiry_hours: Token lifetime in hours (default 1).

    Returns:
        Encoded JWT string.

    Raises:
        ValueError: If the role is not defined in ROLE_PERMISSIONS.
    """
    if role not in ROLE_PERMISSIONS:
        raise ValueError(f"Unknown role: {role}")
    payload = {
        "sub": user_id,
        "role": role,
        "permissions": ROLE_PERMISSIONS[role],
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=expiry_hours),
    }
    return jwt.encode(payload, secret_key, algorithm="HS256")


def verify_token(token: str, secret_key: str) -> dict:
    """
    Decode and verify a JWT, raising HTTP exceptions on failure.

    Returns:
        Decoded payload dict including `sub`, `role`, and `permissions`.

    Raises:
        HTTPException 401: Token expired or otherwise invalid.
    """
    try:
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def check_permission(token_data: dict, required_permission: str) -> bool:
    """Return True if token_data's permissions list includes required_permission."""
    return required_permission in token_data.get("permissions", [])


class RBACMiddleware(BaseHTTPMiddleware):
    """
    Starlette middleware that enforces JWT authentication on all routes except
    those listed in UNPROTECTED_PATHS.

    On success, attaches the decoded token payload to ``request.state.user``.
    Raises HTTP 403 if no Bearer token is present.
    Raises HTTP 401 if the token is expired or invalid (propagated from verify_token).
    """

    def __init__(self, app, secret_key: str):
        super().__init__(app)
        self.secret_key = secret_key

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in UNPROTECTED_PATHS:
            return await call_next(request)
        if any(path.startswith(prefix) for prefix in UNPROTECTED_PREFIXES):
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=403,
                detail="Missing or invalid Authorization header",
            )

        token = auth_header.split(" ", 1)[1]
        token_data = verify_token(token, self.secret_key)
        request.state.user = token_data
        return await call_next(request)
