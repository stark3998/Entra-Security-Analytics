"""JWT validation for Entra ID tokens (interactive / delegated auth).

Fetches JWKS from the Entra OIDC metadata endpoint, caches keys in-memory,
and validates bearer tokens sent by the MSAL.js SPA.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx
import jwt  # PyJWT
from fastapi import Depends, HTTPException, Request, status

from app.config import Settings, get_settings

logger = logging.getLogger(__name__)

# ── JWKS cache ────────────────────────────────────────────────

_jwks_cache: dict[str, Any] = {}
_jwks_cache_expiry: float = 0.0
JWKS_CACHE_TTL = 24 * 3600  # 24 hours


async def _fetch_jwks(tenant_id: str) -> dict[str, Any]:
    """Download JWKS from the Entra v2 OIDC metadata endpoint."""
    global _jwks_cache, _jwks_cache_expiry  # noqa: PLW0603

    now = time.time()
    if _jwks_cache and now < _jwks_cache_expiry:
        return _jwks_cache

    oidc_url = (
        f"https://login.microsoftonline.com/{tenant_id}/v2.0"
        "/.well-known/openid-configuration"
    )
    async with httpx.AsyncClient(timeout=10.0) as client:
        meta_resp = await client.get(oidc_url)
        meta_resp.raise_for_status()
        jwks_uri = meta_resp.json()["jwks_uri"]

        jwks_resp = await client.get(jwks_uri)
        jwks_resp.raise_for_status()
        _jwks_cache = jwks_resp.json()
        _jwks_cache_expiry = now + JWKS_CACHE_TTL

    logger.debug("Refreshed JWKS cache from %s", jwks_uri)
    return _jwks_cache


def _find_signing_key(jwks: dict[str, Any], kid: str) -> jwt.PyJWK:
    """Find the matching JWK by key-id from the JWKS set."""
    for key_data in jwks.get("keys", []):
        if key_data.get("kid") == kid:
            return jwt.PyJWK(key_data)
    raise ValueError(f"Signing key '{kid}' not found in JWKS")


async def validate_entra_token(
    token: str,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Validate an Entra ID v2 JWT and return claims.

    Raises:
        HTTPException(401) on any validation failure.
    """
    settings = settings or get_settings()
    tenant_id = settings.azure_tenant_id

    try:
        # Decode header to get kid
        unverified = jwt.get_unverified_header(token)
        kid = unverified.get("kid", "")

        jwks = await _fetch_jwks(tenant_id)
        signing_key = _find_signing_key(jwks, kid)

        # Determine expected audience
        audience = settings.jwt_audience or settings.effective_frontend_client_id

        issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"

        claims: dict[str, Any] = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=audience,
            issuer=issuer,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
        return claims

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except jwt.InvalidAudienceError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token audience",
        )
    except jwt.InvalidIssuerError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token issuer",
        )
    except (jwt.DecodeError, jwt.InvalidTokenError, ValueError) as exc:
        logger.warning("Token validation failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or malformed token",
        )


# ── FastAPI dependencies ──────────────────────────────────────


def _extract_bearer(request: Request) -> str | None:
    """Extract bearer token from the Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


async def get_current_user(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> dict[str, Any] | None:
    """Validate the bearer token when interactive auth is enabled.

    - client_credentials mode → returns None (no user needed, routes open).
    - interactive / both mode → validates JWT, returns user claims dict.
    """
    if settings.auth_mode == "client_credentials":
        return None

    token = _extract_bearer(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing or invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return await validate_entra_token(token, settings)


async def optional_current_user(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> dict[str, Any] | None:
    """Like get_current_user but never raises — returns None if no valid token."""
    token = _extract_bearer(request)
    if not token:
        return None
    try:
        return await validate_entra_token(token, settings)
    except HTTPException:
        return None


def reset_jwks_cache() -> None:
    """Reset JWKS cache (useful in tests)."""
    global _jwks_cache, _jwks_cache_expiry  # noqa: PLW0603
    _jwks_cache = {}
    _jwks_cache_expiry = 0.0
