"""Auth configuration & settings API routes.

Provides:
- GET /api/auth/config   – Public; returns MSAL.js bootstrap config
- GET /api/auth/me       – Protected; returns current user claims
- GET /api/settings      – Returns current auth mode + status flags
- PUT /api/settings      – Updates auth mode / app-registration details
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.auth.msal_client import reset_auth_client
from app.auth.token_validator import get_current_user
from app.config import get_settings, reset_settings
from app.models.database import AppSettings, get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])
settings_router = APIRouter(prefix="/api/settings", tags=["settings"])


# ── Public: SPA bootstrap config ──────────────────────────────


@router.get("/config")
def auth_config():
    """Return the MSAL.js configuration the SPA needs to initialise."""
    settings = get_settings()
    return {
        "auth_mode": settings.auth_mode,
        "tenant_id": settings.azure_tenant_id,
        "client_id": settings.effective_frontend_client_id,
        "authority": (
            f"https://login.microsoftonline.com/{settings.azure_tenant_id}"
            if settings.azure_tenant_id
            else ""
        ),
        "scopes": ["openid", "profile", "User.Read"],
    }


# ── Protected: current user info ──────────────────────────────


@router.get("/me")
async def auth_me(user: dict[str, Any] | None = Depends(get_current_user)):
    """Return the authenticated user's claims."""
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return {
        "oid": user.get("oid", ""),
        "preferred_username": user.get("preferred_username", ""),
        "name": user.get("name", ""),
        "roles": user.get("roles", []),
    }


# ── Settings CRUD ─────────────────────────────────────────────


class SettingsResponse(BaseModel):
    auth_mode: str
    azure_tenant_id: str
    azure_client_id: str
    frontend_client_id: str
    jwt_audience: str
    client_credentials_configured: bool
    has_client_secret: bool
    interactive_auth_enabled: bool
    available_collectors: list[str]


class SettingsUpdate(BaseModel):
    auth_mode: str | None = None
    azure_tenant_id: str | None = None
    azure_client_id: str | None = None
    azure_client_secret: str | None = None
    frontend_client_id: str | None = None
    jwt_audience: str | None = None

    @field_validator("auth_mode")
    @classmethod
    def _validate_mode(cls, v: str | None) -> str | None:
        if v is not None:
            allowed = {"client_credentials", "interactive", "both"}
            if v.lower() not in allowed:
                msg = f"auth_mode must be one of {allowed}"
                raise ValueError(msg)
            return v.lower()
        return v


def _get_or_create_app_settings(db: Session) -> AppSettings:
    """Return the single AppSettings row, creating from env if absent."""
    row = db.query(AppSettings).filter_by(id=1).first()
    if row is None:
        settings = get_settings()
        row = AppSettings(
            id=1,
            auth_mode=settings.auth_mode,
            azure_tenant_id=settings.azure_tenant_id,
            azure_client_id=settings.azure_client_id,
            azure_client_secret=settings.azure_client_secret,
            frontend_client_id=settings.frontend_client_id,
            jwt_audience=settings.jwt_audience,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def _collectors_for_mode(app_row: AppSettings) -> list[str]:
    """Determine which collectors are available given current config."""
    collectors: list[str] = []
    has_creds = bool(
        app_row.azure_tenant_id
        and app_row.azure_client_id
        and app_row.azure_client_secret
    )
    mode = app_row.auth_mode

    # Graph collectors (Entra sign-in + audit) work with client creds
    if has_creds or mode in ("interactive", "both"):
        collectors.extend(["entra_signin", "entra_audit"])

    # O365 collectors require client creds (delegated not supported)
    if has_creds:
        collectors.extend(["office365", "sharepoint", "powerapps"])

    return collectors


@settings_router.get("", response_model=SettingsResponse)
def get_app_settings(db: Session = Depends(get_db)):
    """Return current auth/app-registration settings (secrets redacted)."""
    row = _get_or_create_app_settings(db)
    has_creds = bool(
        row.azure_tenant_id and row.azure_client_id and row.azure_client_secret
    )
    return SettingsResponse(
        auth_mode=row.auth_mode,
        azure_tenant_id=row.azure_tenant_id or "",
        azure_client_id=row.azure_client_id or "",
        frontend_client_id=row.frontend_client_id or "",
        jwt_audience=row.jwt_audience or "",
        client_credentials_configured=has_creds,
        has_client_secret=bool(row.azure_client_secret),
        interactive_auth_enabled=row.auth_mode in ("interactive", "both"),
        available_collectors=_collectors_for_mode(row),
    )


@settings_router.put("", response_model=SettingsResponse)
def update_app_settings(
    body: SettingsUpdate,
    db: Session = Depends(get_db),
):
    """Update auth mode and/or app-registration details."""
    row = _get_or_create_app_settings(db)

    if body.auth_mode is not None:
        row.auth_mode = body.auth_mode
    if body.azure_tenant_id is not None:
        row.azure_tenant_id = body.azure_tenant_id
    if body.azure_client_id is not None:
        row.azure_client_id = body.azure_client_id
    if body.azure_client_secret is not None:
        row.azure_client_secret = body.azure_client_secret
    if body.frontend_client_id is not None:
        row.frontend_client_id = body.frontend_client_id
    if body.jwt_audience is not None:
        row.jwt_audience = body.jwt_audience

    db.commit()
    db.refresh(row)

    # Hot-reload singletons so new creds take effect immediately
    reset_auth_client()
    reset_settings()

    logger.info("App settings updated: auth_mode=%s", row.auth_mode)

    has_creds = bool(
        row.azure_tenant_id and row.azure_client_id and row.azure_client_secret
    )
    return SettingsResponse(
        auth_mode=row.auth_mode,
        azure_tenant_id=row.azure_tenant_id or "",
        azure_client_id=row.azure_client_id or "",
        frontend_client_id=row.frontend_client_id or "",
        jwt_audience=row.jwt_audience or "",
        client_credentials_configured=has_creds,
        has_client_secret=bool(row.azure_client_secret),
        interactive_auth_enabled=row.auth_mode in ("interactive", "both"),
        available_collectors=_collectors_for_mode(row),
    )
