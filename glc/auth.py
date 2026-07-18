"""Shared HTTP auth for the gateway data plane.

`require_install_token` is a FastAPI dependency that enforces the
per-installation Bearer token (the same token used by /v1/control/* and the
channels WebSocket). Attach it via `include_router(..., dependencies=[...])`
to protect a whole router.
"""

from __future__ import annotations

from fastapi import Header, HTTPException

from glc.config import get_or_create_install_token


def require_install_token(authorization: str | None = Header(default=None)) -> None:
    """Raise 401 if the Bearer token is missing/malformed, 403 if it mismatches."""
    expected = get_or_create_install_token()
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token (Authorization: Bearer <install_token>)")
    presented = authorization.removeprefix("Bearer ").strip()
    if presented != expected:
        raise HTTPException(403, "install token mismatch")
