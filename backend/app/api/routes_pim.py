"""API routes for Privileged Identity Management (PIM) dashboard."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.auth.msal_client import TokenAcquisitionError, get_auth_client
from app.collectors.pim import PIMCollector, PIMCollectorError
from app.models.database import (
    AuditLog,
    PIMActivationRequest,
    PIMRoleAssignment,
    PIMRoleDefinition,
    PIMRoleEligibility,
    get_db,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/pim", tags=["pim"])

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 200


def _clamp(limit: int) -> int:
    return max(1, min(limit, _MAX_LIMIT))


# ── Role Definitions ─────────────────────────────────────────


@router.get("/role-definitions")
def list_role_definitions(db: Session = Depends(get_db)):
    roles = db.query(PIMRoleDefinition).order_by(PIMRoleDefinition.display_name).all()
    return {
        "total": len(roles),
        "items": [_role_def_to_dict(r) for r in roles],
    }


# ── Assignments ──────────────────────────────────────────────


@router.get("/assignments")
def list_assignments(
    db: Session = Depends(get_db),
    offset: int = Query(0, ge=0),
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    role: str | None = None,
    principal: str | None = None,
    assignment_type: str | None = None,
):
    q = db.query(PIMRoleAssignment)
    if role:
        q = q.filter(PIMRoleAssignment.role_display_name.ilike(f"%{role}%"))
    if principal:
        q = q.filter(
            or_(
                PIMRoleAssignment.principal_display_name.ilike(f"%{principal}%"),
                PIMRoleAssignment.principal_id.ilike(f"%{principal}%"),
            )
        )
    if assignment_type:
        q = q.filter(PIMRoleAssignment.assignment_type == assignment_type)

    total = q.count()
    items = (
        q.order_by(PIMRoleAssignment.role_display_name, PIMRoleAssignment.principal_display_name)
        .offset(offset)
        .limit(_clamp(limit))
        .all()
    )
    return {
        "total": total,
        "offset": offset,
        "limit": _clamp(limit),
        "items": [_assignment_to_dict(a) for a in items],
    }


# ── Eligibilities ────────────────────────────────────────────


@router.get("/eligibilities")
def list_eligibilities(
    db: Session = Depends(get_db),
    offset: int = Query(0, ge=0),
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    role: str | None = None,
    principal: str | None = None,
):
    q = db.query(PIMRoleEligibility)
    if role:
        q = q.filter(PIMRoleEligibility.role_display_name.ilike(f"%{role}%"))
    if principal:
        q = q.filter(
            or_(
                PIMRoleEligibility.principal_display_name.ilike(f"%{principal}%"),
                PIMRoleEligibility.principal_id.ilike(f"%{principal}%"),
            )
        )

    total = q.count()
    items = (
        q.order_by(PIMRoleEligibility.role_display_name, PIMRoleEligibility.principal_display_name)
        .offset(offset)
        .limit(_clamp(limit))
        .all()
    )
    return {
        "total": total,
        "offset": offset,
        "limit": _clamp(limit),
        "items": [_eligibility_to_dict(e) for e in items],
    }


# ── Activations ──────────────────────────────────────────────


@router.get("/activations")
def list_activations(
    db: Session = Depends(get_db),
    offset: int = Query(0, ge=0),
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    role: str | None = None,
    principal: str | None = None,
    action: str | None = None,
    status: str | None = None,
):
    q = db.query(PIMActivationRequest)
    if role:
        q = q.filter(PIMActivationRequest.role_display_name.ilike(f"%{role}%"))
    if principal:
        q = q.filter(
            or_(
                PIMActivationRequest.principal_display_name.ilike(f"%{principal}%"),
                PIMActivationRequest.principal_id.ilike(f"%{principal}%"),
            )
        )
    if action:
        q = q.filter(PIMActivationRequest.action.ilike(f"%{action}%"))
    if status:
        q = q.filter(PIMActivationRequest.status == status)

    total = q.count()
    items = (
        q.order_by(PIMActivationRequest.created_date_time.desc())
        .offset(offset)
        .limit(_clamp(limit))
        .all()
    )
    return {
        "total": total,
        "offset": offset,
        "limit": _clamp(limit),
        "items": [_activation_to_dict(a) for a in items],
    }


# ── PIM Audit Logs (from existing AuditLog table) ───────────


@router.get("/audit-logs")
def pim_audit_logs(
    db: Session = Depends(get_db),
    offset: int = Query(0, ge=0),
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    activity: str | None = None,
    user: str | None = None,
):
    q = db.query(AuditLog).filter(AuditLog.category == "RoleManagement")
    if activity:
        q = q.filter(AuditLog.activity_display_name.ilike(f"%{activity}%"))
    if user:
        q = q.filter(
            or_(
                AuditLog.initiated_by_user_upn.ilike(f"%{user}%"),
                AuditLog.initiated_by_user_display_name.ilike(f"%{user}%"),
            )
        )

    total = q.count()
    items = (
        q.order_by(AuditLog.activity_date_time.desc())
        .offset(offset)
        .limit(_clamp(limit))
        .all()
    )
    return {
        "total": total,
        "offset": offset,
        "limit": _clamp(limit),
        "items": [_audit_to_dict(a) for a in items],
    }


# ── Stats (KPIs) ────────────────────────────────────────────


@router.get("/stats")
def pim_stats(db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(days=1)
    week_ago = now - timedelta(days=7)

    total_assignments = db.query(func.count(PIMRoleAssignment.id)).scalar() or 0
    total_eligibilities = db.query(func.count(PIMRoleEligibility.id)).scalar() or 0
    permanent_assignments = (
        db.query(func.count(PIMRoleAssignment.id))
        .filter(PIMRoleAssignment.end_date_time.is_(None))
        .scalar() or 0
    )
    activations_24h = (
        db.query(func.count(PIMActivationRequest.id))
        .filter(
            PIMActivationRequest.action.ilike("%activate%"),
            PIMActivationRequest.created_date_time >= day_ago,
        )
        .scalar() or 0
    )
    activations_7d = (
        db.query(func.count(PIMActivationRequest.id))
        .filter(
            PIMActivationRequest.action.ilike("%activate%"),
            PIMActivationRequest.created_date_time >= week_ago,
        )
        .scalar() or 0
    )

    return {
        "total_assignments": total_assignments,
        "total_eligibilities": total_eligibilities,
        "permanent_assignments": permanent_assignments,
        "activations_24h": activations_24h,
        "activations_7d": activations_7d,
    }


# ── Insights ─────────────────────────────────────────────────


@router.get("/insights")
def pim_insights(db: Session = Depends(get_db)):
    # Top activated roles
    top_roles = (
        db.query(
            PIMActivationRequest.role_display_name,
            func.count(PIMActivationRequest.id).label("count"),
        )
        .filter(PIMActivationRequest.action.ilike("%activate%"))
        .group_by(PIMActivationRequest.role_display_name)
        .order_by(func.count(PIMActivationRequest.id).desc())
        .limit(10)
        .all()
    )

    # Top activating users
    top_users = (
        db.query(
            PIMActivationRequest.principal_display_name,
            func.count(PIMActivationRequest.id).label("count"),
        )
        .filter(PIMActivationRequest.action.ilike("%activate%"))
        .group_by(PIMActivationRequest.principal_display_name)
        .order_by(func.count(PIMActivationRequest.id).desc())
        .limit(10)
        .all()
    )

    # Role distribution: active + eligible counts per role
    active_by_role = dict(
        db.query(
            PIMRoleAssignment.role_display_name,
            func.count(PIMRoleAssignment.id),
        )
        .group_by(PIMRoleAssignment.role_display_name)
        .all()
    )
    eligible_by_role = dict(
        db.query(
            PIMRoleEligibility.role_display_name,
            func.count(PIMRoleEligibility.id),
        )
        .group_by(PIMRoleEligibility.role_display_name)
        .all()
    )
    all_roles = sorted(set(active_by_role.keys()) | set(eligible_by_role.keys()))
    role_distribution = [
        {
            "role": role,
            "active": active_by_role.get(role, 0),
            "eligible": eligible_by_role.get(role, 0),
        }
        for role in all_roles
    ]

    # Permanent vs time-bound
    total_assignments = db.query(func.count(PIMRoleAssignment.id)).scalar() or 0
    permanent = (
        db.query(func.count(PIMRoleAssignment.id))
        .filter(PIMRoleAssignment.end_date_time.is_(None))
        .scalar() or 0
    )

    return {
        "top_activated_roles": [{"role": r, "count": c} for r, c in top_roles],
        "top_activating_users": [{"user": u, "count": c} for u, c in top_users],
        "role_distribution": role_distribution,
        "permanent_vs_timebound": {
            "permanent": permanent,
            "time_bound": total_assignments - permanent,
        },
    }


# ── Sync ─────────────────────────────────────────────────────


@router.post("/sync", status_code=200)
async def sync_pim(db: Session = Depends(get_db)):
    """Trigger a full sync of PIM data from Graph API."""
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

    collector = PIMCollector()
    try:
        counts = await collector.sync_all(token, db)
    except PIMCollectorError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        await collector.close()

    return {"status": "ok", "synced": counts}


# ── Serialisation helpers ─────────────────────────────────────


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _role_def_to_dict(r: PIMRoleDefinition) -> dict[str, Any]:
    return {
        "id": r.id,
        "display_name": r.display_name,
        "description": r.description,
        "is_built_in": r.is_built_in,
        "is_enabled": r.is_enabled,
    }


def _assignment_to_dict(a: PIMRoleAssignment) -> dict[str, Any]:
    return {
        "id": a.id,
        "principal_id": a.principal_id,
        "principal_display_name": a.principal_display_name,
        "principal_type": a.principal_type,
        "role_definition_id": a.role_definition_id,
        "role_display_name": a.role_display_name,
        "directory_scope_id": a.directory_scope_id,
        "assignment_type": a.assignment_type,
        "member_type": a.member_type,
        "start_date_time": _iso(a.start_date_time),
        "end_date_time": _iso(a.end_date_time),
        "is_permanent": a.end_date_time is None,
        "raw_json": a.raw_json,
    }


def _eligibility_to_dict(e: PIMRoleEligibility) -> dict[str, Any]:
    return {
        "id": e.id,
        "principal_id": e.principal_id,
        "principal_display_name": e.principal_display_name,
        "principal_type": e.principal_type,
        "role_definition_id": e.role_definition_id,
        "role_display_name": e.role_display_name,
        "directory_scope_id": e.directory_scope_id,
        "member_type": e.member_type,
        "start_date_time": _iso(e.start_date_time),
        "end_date_time": _iso(e.end_date_time),
        "raw_json": e.raw_json,
    }


def _activation_to_dict(a: PIMActivationRequest) -> dict[str, Any]:
    return {
        "id": a.id,
        "principal_id": a.principal_id,
        "principal_display_name": a.principal_display_name,
        "role_definition_id": a.role_definition_id,
        "role_display_name": a.role_display_name,
        "action": a.action,
        "status": a.status,
        "justification": a.justification,
        "created_date_time": _iso(a.created_date_time),
        "schedule_start": _iso(a.schedule_start),
        "schedule_end": _iso(a.schedule_end),
        "raw_json": a.raw_json,
    }


def _audit_to_dict(a: AuditLog) -> dict[str, Any]:
    return {
        "id": a.id,
        "activity_display_name": a.activity_display_name,
        "activity_date_time": _iso(a.activity_date_time),
        "category": a.category,
        "result": a.result,
        "result_reason": a.result_reason,
        "initiated_by_user_upn": a.initiated_by_user_upn,
        "initiated_by_user_display_name": a.initiated_by_user_display_name,
        "initiated_by_app_display_name": a.initiated_by_app_display_name,
        "target_resources": a.target_resources,
        "additional_details": a.additional_details,
        "raw_json": a.raw_json,
    }
