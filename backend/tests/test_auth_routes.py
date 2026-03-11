"""Tests for app.api.routes_auth – Auth config & settings CRUD endpoints.

Covers:
- GET /api/auth/config (public MSAL bootstrap config)
- GET /api/auth/me (protected user claims)
- GET /api/settings (read current settings)
- PUT /api/settings (update auth mode & app registration)
- _collectors_for_mode logic
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from app.api.routes_auth import _collectors_for_mode
from app.models.database import AppSettings


# ── Tests: GET /api/auth/config ───────────────────────────────


class TestAuthConfig:
    def test_returns_config(self, client):
        """Auth config is publicly accessible."""
        resp = client.get("/api/auth/config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_mode"] == "client_credentials"
        assert data["tenant_id"] == "test-tenant-id"
        assert "scopes" in data
        assert isinstance(data["scopes"], list)

    def test_interactive_mode_config(self, interactive_client):
        """Auth config reflects interactive mode settings."""
        resp = interactive_client.get("/api/auth/config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_mode"] == "interactive"
        assert data["client_id"] == "test-frontend-client-id"
        assert "login.microsoftonline.com" in data["authority"]


# ── Tests: GET /api/auth/me ───────────────────────────────────


class TestAuthMe:
    def test_client_credentials_mode_returns_401(self, client):
        """In client_credentials mode, /me returns 401 (no user context)."""
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401

    def test_interactive_no_token_returns_401(self, interactive_client):
        """In interactive mode without token, /me returns 401."""
        resp = interactive_client.get("/api/auth/me")
        assert resp.status_code == 401

    def test_interactive_with_valid_user(self, interactive_client):
        """In interactive mode with mock user, /me returns user claims."""
        from app.auth.token_validator import get_current_user

        fake_user = {
            "oid": "user-oid-123",
            "preferred_username": "alice@contoso.com",
            "name": "Alice Smith",
            "roles": ["admin"],
        }

        interactive_client.app.dependency_overrides[get_current_user] = lambda: fake_user
        try:
            resp = interactive_client.get("/api/auth/me")
            assert resp.status_code == 200
            data = resp.json()
            assert data["oid"] == "user-oid-123"
            assert data["preferred_username"] == "alice@contoso.com"
        finally:
            del interactive_client.app.dependency_overrides[get_current_user]


# ── Tests: GET /api/settings ──────────────────────────────────


class TestGetSettings:
    def test_returns_default_settings(self, client):
        """Settings endpoint returns initial config."""
        resp = client.get("/api/settings")
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_mode"] == "client_credentials"
        assert data["client_credentials_configured"] is True
        assert isinstance(data["available_collectors"], list)
        assert "entra_signin" in data["available_collectors"]
        assert "office365" in data["available_collectors"]

    def test_interactive_mode_settings(self, interactive_client):
        """Interactive mode settings reflect correct collectors."""
        resp = interactive_client.get("/api/settings")
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_mode"] == "interactive"
        assert data["interactive_auth_enabled"] is True
        assert data["frontend_client_id"] == "test-frontend-client-id"

    def test_has_expected_fields(self, client):
        """Response includes all required fields."""
        resp = client.get("/api/settings")
        data = resp.json()
        required_fields = {
            "auth_mode",
            "azure_tenant_id",
            "azure_client_id",
            "frontend_client_id",
            "jwt_audience",
            "client_credentials_configured",
            "has_client_secret",
            "interactive_auth_enabled",
            "available_collectors",
        }
        assert required_fields.issubset(data.keys())


# ── Tests: PUT /api/settings ──────────────────────────────────


class TestUpdateSettings:
    def test_update_auth_mode(self, client):
        """Can change auth mode via PUT."""
        resp = client.put("/api/settings", json={"auth_mode": "both"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_mode"] == "both"
        assert data["interactive_auth_enabled"] is True

    def test_update_app_registration(self, client):
        """Can update app registration fields."""
        resp = client.put(
            "/api/settings",
            json={
                "azure_tenant_id": "new-tenant",
                "azure_client_id": "new-client",
                "azure_client_secret": "new-secret",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["azure_tenant_id"] == "new-tenant"
        assert data["azure_client_id"] == "new-client"
        assert data["has_client_secret"] is True

    def test_update_frontend_client_id(self, client):
        """Can update frontend client ID for interactive auth."""
        resp = client.put(
            "/api/settings",
            json={"frontend_client_id": "my-spa-client-id"},
        )
        assert resp.status_code == 200
        assert resp.json()["frontend_client_id"] == "my-spa-client-id"

    def test_invalid_auth_mode_rejected(self, client):
        """Invalid auth_mode values are rejected."""
        resp = client.put("/api/settings", json={"auth_mode": "invalid_mode"})
        assert resp.status_code == 422

    def test_partial_update_preserves_existing(self, client):
        """Updating one field doesn't reset others."""
        # First set up initial values
        client.put(
            "/api/settings",
            json={
                "azure_tenant_id": "my-tenant",
                "azure_client_id": "my-client",
            },
        )
        # Now update only auth_mode
        resp = client.put("/api/settings", json={"auth_mode": "interactive"})
        data = resp.json()
        assert data["auth_mode"] == "interactive"
        assert data["azure_tenant_id"] == "my-tenant"
        assert data["azure_client_id"] == "my-client"

    def test_clear_credentials(self, client):
        """Can clear credentials by setting empty strings."""
        client.put(
            "/api/settings",
            json={
                "azure_client_secret": "a-secret",
            },
        )
        resp = client.put("/api/settings", json={"azure_client_secret": ""})
        data = resp.json()
        assert data["has_client_secret"] is False


# ── Tests: _collectors_for_mode ───────────────────────────────


class TestCollectorsForMode:
    def _make_app_settings(self, **kwargs) -> AppSettings:
        defaults = {
            "id": 1,
            "auth_mode": "client_credentials",
            "azure_tenant_id": "t",
            "azure_client_id": "c",
            "azure_client_secret": "s",
        }
        defaults.update(kwargs)
        row = AppSettings(**defaults)
        return row

    def test_client_credentials_all_collectors(self):
        row = self._make_app_settings()
        collectors = _collectors_for_mode(row)
        assert "entra_signin" in collectors
        assert "entra_audit" in collectors
        assert "office365" in collectors
        assert "sharepoint" in collectors
        assert "powerapps" in collectors

    def test_interactive_no_creds(self):
        """Interactive mode without client creds → only Graph collectors."""
        row = self._make_app_settings(
            auth_mode="interactive",
            azure_client_secret="",
        )
        collectors = _collectors_for_mode(row)
        assert "entra_signin" in collectors
        assert "entra_audit" in collectors
        assert "office365" not in collectors
        assert "sharepoint" not in collectors

    def test_both_mode_with_creds(self):
        """Both mode with full creds → all collectors."""
        row = self._make_app_settings(auth_mode="both")
        collectors = _collectors_for_mode(row)
        assert len(collectors) == 5

    def test_client_credentials_no_creds(self):
        """Client credentials mode with NO creds → no collectors."""
        row = self._make_app_settings(
            azure_tenant_id="",
            azure_client_id="",
            azure_client_secret="",
        )
        collectors = _collectors_for_mode(row)
        assert collectors == []
