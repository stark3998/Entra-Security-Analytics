"""Entra ID user directory endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.auth.msal_client import TokenAcquisitionError, get_auth_client
from app.collectors.users import UserCollector, UserCollectorError
from app.models.database import EntraUser, get_db

router = APIRouter(prefix="/api/directory/users", tags=["user-directory"])

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 200


def _clamp(limit: int) -> int:
    return max(1, min(limit, _MAX_LIMIT))


# ── List users ──────────────────────────────────────────────────

@router.get("")
def list_users(
    db: Session = Depends(get_db),
    offset: int = Query(0, ge=0),
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    search: Optional[str] = None,
    user_type: Optional[str] = None,
    account_enabled: Optional[bool] = None,
):
    q = db.query(EntraUser)

    if search:
        pattern = f"%{search}%"
        q = q.filter(
            or_(
                EntraUser.display_name.ilike(pattern),
                EntraUser.user_principal_name.ilike(pattern),
                EntraUser.department.ilike(pattern),
                EntraUser.job_title.ilike(pattern),
                EntraUser.mail.ilike(pattern),
            )
        )

    if user_type:
        q = q.filter(EntraUser.user_type.ilike(user_type))

    if account_enabled is not None:
        q = q.filter(EntraUser.account_enabled == account_enabled)

    total = q.count()
    items = (
        q.order_by(EntraUser.display_name)
        .offset(offset)
        .limit(_clamp(limit))
        .all()
    )
    return {
        "total": total,
        "offset": offset,
        "limit": _clamp(limit),
        "items": [_user_to_dict(u) for u in items],
    }


# ── Stats ───────────────────────────────────────────────────────

@router.get("/stats")
def user_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(EntraUser.id)).scalar() or 0
    guests = (
        db.query(func.count(EntraUser.id))
        .filter(EntraUser.user_type == "Guest")
        .scalar() or 0
    )
    disabled = (
        db.query(func.count(EntraUser.id))
        .filter(EntraUser.account_enabled == False)  # noqa: E712
        .scalar() or 0
    )
    licensed = (
        db.query(func.count(EntraUser.id))
        .filter(func.json_array_length(EntraUser.assigned_licenses) > 0)
        .scalar() or 0
    )
    return {
        "total": total,
        "guests": guests,
        "disabled": disabled,
        "licensed": licensed,
    }


# ── Single user by ID ──────────────────────────────────────────

@router.get("/by-upn/{upn}")
def get_user_by_upn(upn: str, db: Session = Depends(get_db)):
    user = db.query(EntraUser).filter(EntraUser.user_principal_name == upn).first()
    if not user:
        raise HTTPException(404, "User not found")
    return _user_to_dict(user)


@router.get("/{user_id}")
def get_user(user_id: str, db: Session = Depends(get_db)):
    user = db.query(EntraUser).get(user_id)
    if not user:
        raise HTTPException(404, "User not found")
    return _user_to_dict(user)


# ── Sync ────────────────────────────────────────────────────────

@router.post("/sync", status_code=200)
async def sync_users(db: Session = Depends(get_db)):
    """Trigger a full sync of Entra ID users from Graph API."""
    auth_client = get_auth_client()
    if not auth_client.is_configured:
        raise HTTPException(
            status_code=503,
            detail="MSAL client not configured — set app registration credentials first",
        )

    try:
        token = auth_client.get_graph_token()
    except TokenAcquisitionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    collector = UserCollector()
    try:
        counts = await collector.sync_all(token, db)
    except UserCollectorError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        await collector.close()

    return {"status": "ok", "synced": counts}


# ── Serialisation ───────────────────────────────────────────────

def _user_to_dict(u: EntraUser) -> dict:
    return {
        "id": u.id,
        "user_principal_name": u.user_principal_name,
        "display_name": u.display_name,
        "mail": u.mail,
        "job_title": u.job_title,
        "department": u.department,
        "office_location": u.office_location,
        "mobile_phone": u.mobile_phone,
        "company_name": u.company_name,
        "account_enabled": u.account_enabled,
        "user_type": u.user_type,
        "created_date_time": u.created_date_time.isoformat() if u.created_date_time else None,
        "last_sign_in_date_time": u.last_sign_in_date_time.isoformat() if u.last_sign_in_date_time else None,
        "assigned_licenses": u.assigned_licenses or [],
        "assigned_plans": u.assigned_plans or [],
        "raw_json": u.raw_json or {},
        "synced_at": u.synced_at.isoformat() if u.synced_at else None,
    }
