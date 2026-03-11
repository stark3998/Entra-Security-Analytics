"""Dashboard summary endpoints — risk scores, stats, recent activity."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.analyzers.risk_scorer import RiskScorer
from app.models.database import (
    AuditLog,
    Incident,
    IncidentStatus,
    LogSource,
    O365ActivityLog,
    Severity,
    SignInLog,
    UserWatchState,
    get_db,
)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary")
def dashboard_summary(db: Session = Depends(get_db)):
    """Top-level KPI summary for the dashboard."""
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    open_statuses = [IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]

    open_incidents = db.query(func.count()).filter(
        Incident.status.in_(open_statuses)
    ).scalar() or 0

    critical_incidents_24h = db.query(func.count()).filter(
        Incident.created_at >= last_24h,
        Incident.severity == Severity.CRITICAL,
    ).scalar() or 0

    incidents_7d = db.query(func.count()).filter(
        Incident.created_at >= last_7d,
    ).scalar() or 0

    active_watches = db.query(func.count()).filter(
        UserWatchState.is_active.is_(True),
    ).scalar() or 0

    signin_count_24h = db.query(func.count()).filter(
        SignInLog.created_date_time >= last_24h,
    ).scalar() or 0

    return {
        "open_incidents": open_incidents,
        "critical_incidents_24h": critical_incidents_24h,
        "incidents_7d": incidents_7d,
        "active_watch_windows": active_watches,
        "signin_events_24h": signin_count_24h,
    }


@router.get("/risk-scores")
def risk_scores(
    db: Session = Depends(get_db),
    threshold: int = Query(0, ge=0, le=100),
):
    """Return risk scores for all watched users (or those above threshold)."""
    scorer = RiskScorer(db)
    if threshold > 0:
        results = scorer.get_high_risk_users(threshold=threshold)
    else:
        results = scorer.score_all_watched_users()
    return {"users": [r.to_dict() for r in results]}


@router.get("/incident-trend")
def incident_trend(
    db: Session = Depends(get_db),
    days: int = Query(30, ge=1, le=90),
):
    """Daily incident counts for trend chart."""
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    rows = (
        db.query(
            func.date(Incident.created_at).label("day"),
            Incident.severity,
            func.count().label("count"),
        )
        .filter(Incident.created_at >= since)
        .group_by(func.date(Incident.created_at), Incident.severity)
        .order_by(func.date(Incident.created_at))
        .all()
    )
    trend: dict[str, dict[str, int]] = {}
    for day, sev, count in rows:
        d = str(day)
        if d not in trend:
            trend[d] = {}
        trend[d][sev.value] = count
    return {"days": days, "trend": trend}


@router.get("/log-volume")
def log_volume(
    db: Session = Depends(get_db),
    days: int = Query(7, ge=1, le=30),
):
    """Per-source log ingestion volume over recent days."""
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)

    signin_count = db.query(func.count()).filter(
        SignInLog.created_date_time >= since,
    ).scalar() or 0
    audit_count = db.query(func.count()).filter(
        AuditLog.activity_date_time >= since,
    ).scalar() or 0

    activity_counts = (
        db.query(O365ActivityLog.source, func.count())
        .filter(O365ActivityLog.creation_time >= since)
        .group_by(O365ActivityLog.source)
        .all()
    )
    activity_map = {s.value: c for s, c in activity_counts}

    return {
        "days": days,
        "volumes": {
            "entra_signin": signin_count,
            "entra_audit": audit_count,
            "office365": activity_map.get(LogSource.OFFICE365.value, 0),
            "sharepoint": activity_map.get(LogSource.SHAREPOINT.value, 0),
            "powerapps": activity_map.get(LogSource.POWERAPPS.value, 0),
        },
    }


@router.get("/watched-users")
def watched_users(db: Session = Depends(get_db)):
    """Active user watch windows."""
    windows = (
        db.query(UserWatchState)
        .filter(UserWatchState.is_active.is_(True))
        .order_by(UserWatchState.risk_contribution.desc())
        .all()
    )
    return {
        "count": len(windows),
        "users": [
            {
                "user_id": w.user_id,
                "rule_slug": w.rule.slug if w.rule else None,
                "risk_contribution": w.risk_contribution,
                "started_at": w.window_start.isoformat() if w.window_start else None,
                "expires_at": w.window_end.isoformat() if w.window_end else None,
            }
            for w in windows
        ],
    }
