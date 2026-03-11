"""Tests for app.auth.token_validator – JWT validation and FastAPI dependencies.

Covers:
- JWKS fetching & caching
- Token validation (valid, expired, wrong aud, wrong iss, bad kid)
- get_current_user dependency (client_credentials bypass, interactive enforcement)
- optional_current_user dependency
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException

from app.auth.token_validator import (
    _extract_bearer,
    _fetch_jwks,
    _find_signing_key,
    get_current_user,
    optional_current_user,
    reset_jwks_cache,
    validate_entra_token,
)

# ── RSA key pair helpers ──────────────────────────────────────


def _generate_rsa_key_pair():
    """Generate an RSA private key and return (private_key, jwk_dict)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Serialize public numbers for JWK
    pub_numbers = public_key.public_numbers()

    def _int_to_base64url(n: int, length: int) -> str:
        return (
            n.to_bytes(length, byteorder="big")
            .rstrip(b"\x00")  # keep leading zeros, strip trailing
        )

    import base64

    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    e_bytes = pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, "big")
    n_bytes = pub_numbers.n.to_bytes((pub_numbers.n.bit_length() + 7) // 8, "big")

    jwk_dict = {
        "kty": "RSA",
        "use": "sig",
        "kid": "test-kid-001",
        "n": _b64url(n_bytes),
        "e": _b64url(e_bytes),
        "alg": "RS256",
    }
    return private_key, jwk_dict


_PRIVATE_KEY, _JWK_DICT = _generate_rsa_key_pair()
_JWKS = {"keys": [_JWK_DICT]}

TENANT_ID = "test-tenant-id"
CLIENT_ID = "test-frontend-client-id"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"


def _make_jwt(
    claims_override: dict[str, Any] | None = None,
    kid: str = "test-kid-001",
    algorithm: str = "RS256",
) -> str:
    """Create a signed JWT with sensible defaults."""
    now = datetime.now(timezone.utc)
    claims: dict[str, Any] = {
        "aud": CLIENT_ID,
        "iss": ISSUER,
        "sub": "user-oid-123",
        "oid": "user-oid-123",
        "preferred_username": "alice@contoso.com",
        "name": "Alice Smith",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "nbf": int(now.timestamp()),
    }
    if claims_override:
        claims.update(claims_override)

    headers = {"kid": kid, "alg": algorithm}
    return pyjwt.encode(claims, _PRIVATE_KEY, algorithm=algorithm, headers=headers)


def _make_fake_request(token: str | None = None) -> MagicMock:
    """Create a mock FastAPI Request with optional Authorization header."""
    request = MagicMock()
    if token:
        request.headers = {"Authorization": f"Bearer {token}"}
    else:
        request.headers = {}
    return request


# ── Tests: _extract_bearer ────────────────────────────────────


class TestExtractBearer:
    def test_valid_bearer(self):
        request = _make_fake_request("some-token")
        assert _extract_bearer(request) == "some-token"

    def test_no_header(self):
        request = _make_fake_request()
        assert _extract_bearer(request) is None

    def test_wrong_scheme(self):
        request = MagicMock()
        request.headers = {"Authorization": "Basic abc123"}
        assert _extract_bearer(request) is None

    def test_empty_header(self):
        request = MagicMock()
        request.headers = {"Authorization": ""}
        assert _extract_bearer(request) is None


# ── Tests: _find_signing_key ──────────────────────────────────


class TestFindSigningKey:
    def test_found(self):
        key = _find_signing_key(_JWKS, "test-kid-001")
        assert key is not None

    def test_not_found(self):
        with pytest.raises(ValueError, match="Signing key 'bad-kid' not found"):
            _find_signing_key(_JWKS, "bad-kid")

    def test_empty_jwks(self):
        with pytest.raises(ValueError):
            _find_signing_key({"keys": []}, "test-kid-001")


# ── Tests: _fetch_jwks ───────────────────────────────────────


class TestFetchJwks:
    @pytest.fixture(autouse=True)
    def _clear_cache(self):
        reset_jwks_cache()
        yield
        reset_jwks_cache()

    @pytest.mark.asyncio
    async def test_fetches_and_caches(self):
        """First call fetches, second returns cached."""
        mock_meta = {"jwks_uri": "https://login.microsoftonline.com/common/discovery/v2.0/keys"}

        with patch("app.auth.token_validator.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            # Setup response chain: first OIDC metadata, then JWKS
            meta_resp = MagicMock()
            meta_resp.json.return_value = mock_meta
            meta_resp.raise_for_status = MagicMock()

            jwks_resp = MagicMock()
            jwks_resp.json.return_value = _JWKS
            jwks_resp.raise_for_status = MagicMock()

            mock_client.get = AsyncMock(side_effect=[meta_resp, jwks_resp])

            result = await _fetch_jwks(TENANT_ID)
            assert result == _JWKS
            assert mock_client.get.call_count == 2

        # Second call should use cache (no HTTP)
        result2 = await _fetch_jwks(TENANT_ID)
        assert result2 == _JWKS


# ── Tests: validate_entra_token ───────────────────────────────


class TestValidateEntraToken:
    @pytest.fixture(autouse=True)
    def _mock_jwks(self):
        """Patch _fetch_jwks to return our test JWKS."""
        with patch(
            "app.auth.token_validator._fetch_jwks",
            new_callable=AsyncMock,
            return_value=_JWKS,
        ):
            yield

    def _settings(self, **overrides):
        from tests.conftest import _test_settings

        defaults = {
            "auth_mode": "interactive",
            "frontend_client_id": CLIENT_ID,
            "jwt_audience": CLIENT_ID,
        }
        defaults.update(overrides)
        return _test_settings(**defaults)

    @pytest.mark.asyncio
    async def test_valid_token(self):
        token = _make_jwt()
        claims = await validate_entra_token(token, self._settings())
        assert claims["sub"] == "user-oid-123"
        assert claims["preferred_username"] == "alice@contoso.com"

    @pytest.mark.asyncio
    async def test_expired_token(self):
        expired = _make_jwt({"exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())})
        with pytest.raises(HTTPException) as exc_info:
            await validate_entra_token(expired, self._settings())
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_wrong_audience(self):
        token = _make_jwt({"aud": "wrong-client-id"})
        with pytest.raises(HTTPException) as exc_info:
            await validate_entra_token(token, self._settings())
        assert exc_info.value.status_code == 401
        assert "audience" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_wrong_issuer(self):
        token = _make_jwt({"iss": "https://evil.example.com/v2.0"})
        with pytest.raises(HTTPException) as exc_info:
            await validate_entra_token(token, self._settings())
        assert exc_info.value.status_code == 401
        assert "issuer" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_unknown_kid(self):
        token = _make_jwt(kid="unknown-kid-999")
        with pytest.raises(HTTPException) as exc_info:
            await validate_entra_token(token, self._settings())
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_malformed_token(self):
        with pytest.raises(HTTPException) as exc_info:
            await validate_entra_token("not.a.jwt", self._settings())
        assert exc_info.value.status_code == 401


# ── Tests: get_current_user ───────────────────────────────────


class TestGetCurrentUser:
    def _settings(self, mode: str = "client_credentials"):
        from tests.conftest import _test_settings

        return _test_settings(
            auth_mode=mode,
            frontend_client_id=CLIENT_ID,
            jwt_audience=CLIENT_ID,
        )

    @pytest.mark.asyncio
    async def test_client_credentials_returns_none(self):
        """In client_credentials mode, auth is bypassed."""
        request = _make_fake_request()
        result = await get_current_user(request, self._settings("client_credentials"))
        assert result is None

    @pytest.mark.asyncio
    async def test_interactive_no_token_raises(self):
        """In interactive mode, missing token → 401."""
        request = _make_fake_request()
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(request, self._settings("interactive"))
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_both_mode_no_token_raises(self):
        """In both mode, missing token → 401."""
        request = _make_fake_request()
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(request, self._settings("both"))
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_interactive_valid_token(self):
        """In interactive mode, valid JWT → returns claims."""
        token = _make_jwt()
        request = _make_fake_request(token)
        with patch(
            "app.auth.token_validator._fetch_jwks",
            new_callable=AsyncMock,
            return_value=_JWKS,
        ):
            result = await get_current_user(request, self._settings("interactive"))
        assert result is not None
        assert result["oid"] == "user-oid-123"


# ── Tests: optional_current_user ──────────────────────────────


class TestOptionalCurrentUser:
    def _settings(self):
        from tests.conftest import _test_settings

        return _test_settings(
            auth_mode="interactive",
            frontend_client_id=CLIENT_ID,
            jwt_audience=CLIENT_ID,
        )

    @pytest.mark.asyncio
    async def test_no_token_returns_none(self):
        request = _make_fake_request()
        result = await optional_current_user(request, self._settings())
        assert result is None

    @pytest.mark.asyncio
    async def test_invalid_token_returns_none(self):
        request = _make_fake_request("bad-token")
        with patch(
            "app.auth.token_validator._fetch_jwks",
            new_callable=AsyncMock,
            return_value=_JWKS,
        ):
            result = await optional_current_user(request, self._settings())
        assert result is None

    @pytest.mark.asyncio
    async def test_valid_token_returns_claims(self):
        token = _make_jwt()
        request = _make_fake_request(token)
        with patch(
            "app.auth.token_validator._fetch_jwks",
            new_callable=AsyncMock,
            return_value=_JWKS,
        ):
            result = await optional_current_user(request, self._settings())
        assert result is not None
        assert result["preferred_username"] == "alice@contoso.com"
