"""Shared test fixtures and configuration for all backend tests.

Provides:
- In-memory SQLite database per test function (isolated)
- Test Settings override (no real Azure credentials)
- Mock MSAL auth client
- JWT / token validation helpers for auth tests
- Sample data factories for each log type
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure test env vars are set BEFORE importing app modules
os.environ.setdefault("AZURE_TENANT_ID", "test-tenant-id")
os.environ.setdefault("AZURE_CLIENT_ID", "test-client-id")
os.environ.setdefault("AZURE_CLIENT_SECRET", "test-client-secret")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app.config import Settings, get_settings, reset_settings  # noqa: E402
from app.models.database import (  # noqa: E402
    AuditLog,
    AuthenticationStrength,
    Base,
    ConditionalAccessPolicy,
    CorrelationRule,
    DirectoryGroup,
    Incident,
    IncidentStatus,
    LogSource,
    NamedLocation,
    O365ActivityLog,
    PolicyCoverageCache,
    Severity,
    SignInLog,
    UserWatchState,
    reset_db_engine,
)


# ── Test settings ─────────────────────────────────────────────────────────


def _test_settings(**overrides: Any) -> Settings:
    """Build a Settings instance suitable for tests."""
    defaults: dict[str, Any] = {
        "azure_tenant_id": "test-tenant-id",
        "azure_client_id": "test-client-id",
        "azure_client_secret": "test-client-secret",
        "database_url": "sqlite:///:memory:",
        "smtp_host": "",
        "teams_webhook_url": "",
        "slack_webhook_url": "",
        "log_level": "DEBUG",
        "cors_origins": "http://localhost:5173",
        "auth_mode": "client_credentials",
    }
    defaults.update(overrides)
    return Settings(**defaults)  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def _reset_singletons():
    """Reset all module-level singletons between tests."""
    from app.auth.token_validator import reset_jwks_cache

    yield
    reset_settings()
    reset_db_engine()
    reset_jwks_cache()


@pytest.fixture()
def settings() -> Settings:
    return _test_settings()


@pytest.fixture()
def interactive_settings() -> Settings:
    """Settings configured for interactive (SPA) auth mode."""
    return _test_settings(
        auth_mode="interactive",
        frontend_client_id="test-frontend-client-id",
        jwt_audience="test-frontend-client-id",
    )


@pytest.fixture()
def both_mode_settings() -> Settings:
    """Settings configured for 'both' auth mode."""
    return _test_settings(
        auth_mode="both",
        frontend_client_id="test-frontend-client-id",
        jwt_audience="test-frontend-client-id",
    )


# ── Database ──────────────────────────────────────────────────────────────


@pytest.fixture()
def db_engine():
    """Create an in-memory SQLite engine and populate tables."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def db(db_engine) -> Generator[Session, None, None]:
    """Yield a SQLAlchemy session bound to the in-memory database."""
    factory = sessionmaker(bind=db_engine, autoflush=False, expire_on_commit=False)
    session = factory()
    try:
        yield session
    finally:
        session.close()


# ── FastAPI test client ───────────────────────────────────────────────────


@pytest.fixture()
def client(db_engine, settings):
    """Create a TestClient with DB and settings overrides."""
    from fastapi.testclient import TestClient

    from app.main import create_app
    from app.models.database import get_db

    app = create_app()

    # Override DB dependency
    factory = sessionmaker(bind=db_engine, autoflush=False, expire_on_commit=False)

    def _override_get_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _override_get_db

    # Override settings
    with patch("app.config._settings", settings):
        with TestClient(app) as tc:
            yield tc


@pytest.fixture()
def interactive_client(db_engine, interactive_settings):
    """TestClient configured for interactive auth mode (requires JWT)."""
    from fastapi.testclient import TestClient

    from app.main import create_app
    from app.models.database import get_db

    app = create_app()

    factory = sessionmaker(bind=db_engine, autoflush=False, expire_on_commit=False)

    def _override_get_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _override_get_db

    with patch("app.config._settings", interactive_settings):
        with TestClient(app) as tc:
            yield tc


# ── MSAL mock ─────────────────────────────────────────────────────────────


@pytest.fixture()
def mock_msal():
    """Patch MSALAuthClient to return fake tokens."""
    with patch("msal.ConfidentialClientApplication") as mock_cca:
        instance = MagicMock()
        instance.acquire_token_for_client.return_value = {
            "access_token": "fake-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_cca.return_value = instance
        yield instance


# ── Data factories ────────────────────────────────────────────────────────


def make_signin_log(**overrides: Any) -> SignInLog:
    """Create a SignInLog with sensible defaults."""
    defaults: dict[str, Any] = {
        "id": "signin-001",
        "user_id": "user-aad-id-1",
        "user_principal_name": "alice@contoso.com",
        "user_display_name": "Alice Smith",
        "app_display_name": "Office 365",
        "ip_address": "203.0.113.42",
        "location_city": "Seattle",
        "location_country": "US",
        "status_error_code": 0,
        "status_failure_reason": "",
        "risk_level_during_sign_in": "none",
        "risk_level_aggregated": "none",
        "risk_state": "none",
        "is_interactive": True,
        "conditional_access_status": "notApplied",
        "created_date_time": datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
    }
    defaults.update(overrides)
    return SignInLog(**defaults)


def make_audit_log(**overrides: Any) -> AuditLog:
    """Create an AuditLog with sensible defaults."""
    defaults: dict[str, Any] = {
        "id": "audit-001",
        "activity_display_name": "Update user",
        "activity_date_time": datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
        "category": "UserManagement",
        "result": "success",
        "initiated_by_user_upn": "admin@contoso.com",
        "initiated_by_user_display_name": "Admin",
    }
    defaults.update(overrides)
    return AuditLog(**defaults)


def make_activity_log(**overrides: Any) -> O365ActivityLog:
    """Create an O365ActivityLog with sensible defaults."""
    defaults: dict[str, Any] = {
        "id": "activity-001",
        "record_type": 6,
        "creation_time": datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
        "operation": "FileAccessed",
        "user_id": "alice@contoso.com",
        "workload": "SharePoint",
        "source": LogSource.SHAREPOINT,
        "result_status": "Succeeded",
    }
    defaults.update(overrides)
    return O365ActivityLog(**defaults)


def make_correlation_rule(**overrides: Any) -> CorrelationRule:
    """Create a CorrelationRule with sensible defaults."""
    defaults: dict[str, Any] = {
        "slug": "test-rule",
        "name": "Test Rule",
        "severity": Severity.MEDIUM,
        "risk_points": 15,
        "watch_window_days": 14,
        "rule_definition": {
            "triggers": [],
            "watch_window": {"enabled": False, "duration_days": 14, "risk_points": 15},
        },
        "is_system": False,
        "enabled": True,
    }
    defaults.update(overrides)
    return CorrelationRule(**defaults)


def make_incident(rule: CorrelationRule | None = None, **overrides: Any) -> Incident:
    """Create an Incident with sensible defaults."""
    defaults: dict[str, Any] = {
        "title": "Test Incident",
        "severity": Severity.MEDIUM,
        "status": IncidentStatus.OPEN,
        "user_id": "alice@contoso.com",
        "risk_score_at_creation": 15,
    }
    if rule:
        defaults["rule_id"] = rule.id
    defaults.update(overrides)
    return Incident(**defaults)


def make_watch_state(rule: CorrelationRule, **overrides: Any) -> UserWatchState:
    """Create a UserWatchState with sensible defaults."""
    now = datetime.now(timezone.utc)
    from datetime import timedelta

    defaults: dict[str, Any] = {
        "user_id": "alice@contoso.com",
        "rule_id": rule.id,
        "trigger_event_id": "event-001",
        "trigger_event_source": "sign_in_logs",
        "risk_contribution": 15,
        "window_start": now,
        "window_end": now + timedelta(days=14),
        "is_active": True,
    }
    defaults.update(overrides)
    return UserWatchState(**defaults)


# ── CA Policy data factories ─────────────────────────────────────────────


def make_ca_policy(**overrides: Any) -> ConditionalAccessPolicy:
    """Create a ConditionalAccessPolicy with sensible defaults."""
    defaults: dict[str, Any] = {
        "id": "ca-policy-001",
        "display_name": "Require MFA for Admins",
        "state": "enabled",
        "created_date_time": datetime(2024, 3, 1, 12, 0, 0, tzinfo=timezone.utc),
        "modified_date_time": datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
        "conditions": {
            "users": {
                "includeUsers": ["All"],
                "excludeUsers": [],
                "includeGroups": [],
                "excludeGroups": [],
                "includeRoles": ["62e90394-69f5-4237-9190-012177145e10"],
                "excludeRoles": [],
            },
            "applications": {"includeApplications": ["All"], "excludeApplications": []},
        },
        "grant_controls": {"builtInControls": ["mfa"], "operator": "OR"},
        "session_controls": None,
        "raw_json": {},
        "synced_at": datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
    }
    defaults.update(overrides)
    return ConditionalAccessPolicy(**defaults)


def make_named_location(**overrides: Any) -> NamedLocation:
    """Create a NamedLocation with sensible defaults."""
    defaults: dict[str, Any] = {
        "id": "loc-001",
        "display_name": "Corporate Office",
        "is_trusted": True,
        "location_type": "ipNamedLocation",
        "ip_ranges": [{"cidrAddress": "10.0.0.0/8"}],
        "countries_and_regions": [],
        "include_unknown_countries": False,
        "raw_json": {},
        "synced_at": datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
    }
    defaults.update(overrides)
    return NamedLocation(**defaults)


def make_auth_strength(**overrides: Any) -> AuthenticationStrength:
    """Create an AuthenticationStrength with sensible defaults."""
    defaults: dict[str, Any] = {
        "id": "strength-001",
        "display_name": "MFA",
        "description": "Multi-factor authentication",
        "policy_type": "builtIn",
        "requirements_satisfied": "mfa",
        "allowed_combinations": ["password,microsoftAuthenticatorPush"],
        "raw_json": {},
        "synced_at": datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
    }
    defaults.update(overrides)
    return AuthenticationStrength(**defaults)


def make_directory_group(**overrides: Any) -> DirectoryGroup:
    """Create a DirectoryGroup with sensible defaults."""
    defaults: dict[str, Any] = {
        "id": "group-001",
        "display_name": "Engineering Team",
        "object_type": "group",
        "description": "Engineering department group",
        "synced_at": datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
    }
    defaults.update(overrides)
    return DirectoryGroup(**defaults)


def make_coverage_entry(policy: ConditionalAccessPolicy | None = None, **overrides: Any) -> PolicyCoverageCache:
    """Create a PolicyCoverageCache with sensible defaults."""
    defaults: dict[str, Any] = {
        "policy_id": policy.id if policy else "ca-policy-001",
        "entity_type": "user",
        "entity_id": "All",
        "entity_display_name": "All Users",
        "inclusion_type": "include",
        "synced_at": datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
    }
    defaults.update(overrides)
    return PolicyCoverageCache(**defaults)
