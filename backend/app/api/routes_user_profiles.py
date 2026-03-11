"""User sign-in profile endpoints — historical locations, devices, risk flags."""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.analyzers.user_profiles import refresh_all_profiles, refresh_profile_for_user
from app.models.database import SignInLog, UserSignInProfile, get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/users", tags=["user-profiles"])

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 200


def _clamp(limit: int) -> int:
    return max(1, min(limit, _MAX_LIMIT))


# ── List all user profiles ────────────────────────────────────────────────

@router.get("/profiles")
def list_user_profiles(
    db: Session = Depends(get_db),
    offset: int = Query(0, ge=0),
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    risky_only: bool = Query(False),
    search: Optional[str] = None,
):
    """Return paginated list of user sign-in profiles."""
    q = db.query(UserSignInProfile)

    if risky_only:
        q = q.filter(UserSignInProfile.is_risky == True)  # noqa: E712

    if search:
        q = q.filter(
            UserSignInProfile.user_principal_name.ilike(f"%{search}%")
            | UserSignInProfile.user_display_name.ilike(f"%{search}%")
        )

    total = q.count()
    items = (
        q.order_by(desc(UserSignInProfile.last_seen))
        .offset(offset)
        .limit(_clamp(limit))
        .all()
    )
    return {
        "total": total,
        "offset": offset,
        "limit": _clamp(limit),
        "items": [_profile_to_dict(p) for p in items],
    }


# ── Single user profile ──────────────────────────────────────────────────

@router.get("/profiles/{upn}")
def get_user_profile(upn: str, db: Session = Depends(get_db)):
    """Return detailed profile for a single user, plus recent sign-in logs."""
    profile = db.query(UserSignInProfile).filter_by(user_principal_name=upn).first()
    if not profile:
        return {"error": "Profile not found", "user_principal_name": upn}

    # Fetch recent sign-in logs for this user (latest 50)
    recent_logs = (
        db.query(SignInLog)
        .filter(SignInLog.user_principal_name == upn)
        .order_by(desc(SignInLog.created_date_time))
        .limit(50)
        .all()
    )

    return {
        "profile": _profile_to_dict(profile),
        "recent_signin_logs": [_signin_summary(r) for r in recent_logs],
    }


# ── Refresh profiles (manual trigger) ────────────────────────────────────

@router.post("/profiles/refresh")
def refresh_profiles(db: Session = Depends(get_db)):
    """Rebuild all user profiles from sign-in logs."""
    result = refresh_all_profiles(db)
    db.commit()
    return {"status": "ok", **result}


# ── Grouped sign-in logs by user ──────────────────────────────────────────

@router.get("/signin-grouped")
def signin_logs_grouped_by_user(
    db: Session = Depends(get_db),
    offset: int = Query(0, ge=0),
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    search: Optional[str] = None,
    risky_only: bool = Query(False),
):
    """Return sign-in logs grouped by user with profile summary."""
    q = db.query(UserSignInProfile)

    if risky_only:
        q = q.filter(UserSignInProfile.is_risky == True)  # noqa: E712
    if search:
        q = q.filter(
            UserSignInProfile.user_principal_name.ilike(f"%{search}%")
            | UserSignInProfile.user_display_name.ilike(f"%{search}%")
        )

    total = q.count()
    profiles = (
        q.order_by(desc(UserSignInProfile.last_seen))
        .offset(offset)
        .limit(_clamp(limit))
        .all()
    )

    result = []
    for p in profiles:
        recent = (
            db.query(SignInLog)
            .filter(SignInLog.user_principal_name == p.user_principal_name)
            .order_by(desc(SignInLog.created_date_time))
            .limit(10)
            .all()
        )
        result.append({
            "profile": _profile_to_dict(p),
            "recent_logs": [_signin_summary(r) for r in recent],
        })

    return {"total": total, "offset": offset, "limit": _clamp(limit), "items": result}


# ── Serializers ───────────────────────────────────────────────────────────

def _profile_to_dict(p: UserSignInProfile) -> dict:
    return {
        "user_principal_name": p.user_principal_name,
        "user_display_name": p.user_display_name,
        "user_id": p.user_id,
        "known_locations": p.known_locations or [],
        "known_devices": p.known_devices or [],
        "known_ips": p.known_ips or [],
        "sign_in_hour_histogram": p.sign_in_hour_histogram or [0] * 24,
        "total_sign_ins": p.total_sign_ins,
        "first_seen": p.first_seen.isoformat() if p.first_seen else None,
        "last_seen": p.last_seen.isoformat() if p.last_seen else None,
        "is_risky": p.is_risky,
        "risk_reasons": p.risk_reasons or [],
        "risk_flagged_at": p.risk_flagged_at.isoformat() if p.risk_flagged_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }


def _signin_summary(r: SignInLog) -> dict:
    return {
        "id": r.id,
        "created_datetime": r.created_date_time.isoformat() if r.created_date_time else None,
        "ip_address": r.ip_address,
        "location_city": r.location_city,
        "location_country": r.location_country,
        "device_os": r.device_os,
        "device_browser": r.device_browser,
        "risk_level": r.risk_level_during_sign_in,
        "app_display_name": r.app_display_name,
        "status_error_code": r.status_error_code,
        "conditional_access_status": r.conditional_access_status,
    }
