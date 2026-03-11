"""Incident CRUD & status management endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.models.database import CorrelationRule, Incident, IncidentStatus, Severity, get_db

router = APIRouter(prefix="/api/incidents", tags=["incidents"])

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 500


def _clamp(limit: int) -> int:
    return max(1, min(limit, _MAX_LIMIT))


# ── Request / Response schemas ────────────────────────────────────────────

class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None


# ── Endpoints ─────────────────────────────────────────────────────────────

@router.get("")
def list_incidents(
    db: Session = Depends(get_db),
    offset: int = Query(0, ge=0),
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    user: Optional[str] = None,
    rule: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
):
    q = db.query(Incident)
    if status:
        try:
            q = q.filter(Incident.status == IncidentStatus(status))
        except ValueError:
            pass
    if severity:
        try:
            q = q.filter(Incident.severity == Severity(severity))
        except ValueError:
            pass
    if user:
        q = q.filter(Incident.user_id.ilike(f"%{user}%"))
    if rule:
        q = q.join(CorrelationRule, Incident.rule_id == CorrelationRule.id).filter(
            CorrelationRule.slug.ilike(f"%{rule}%")
        )
    if since:
        q = q.filter(Incident.created_at >= since)
    if until:
        q = q.filter(Incident.created_at <= until)

    total = q.count()
    items = (
        q.order_by(desc(Incident.created_at))
        .offset(offset)
        .limit(_clamp(limit))
        .all()
    )
    return {"total": total, "offset": offset, "limit": _clamp(limit), "items": [_inc_to_dict(i) for i in items]}


@router.get("/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    inc = db.query(Incident).get(incident_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    return _inc_to_dict(inc)


@router.patch("/{incident_id}")
def update_incident(incident_id: int, body: IncidentUpdate, db: Session = Depends(get_db)):
    inc = db.query(Incident).get(incident_id)
    if not inc:
        raise HTTPException(404, "Incident not found")

    if body.status is not None:
        try:
            inc.status = IncidentStatus(body.status)
        except ValueError:
            raise HTTPException(400, f"Invalid status: {body.status}")
    if body.assigned_to is not None:
        inc.assigned_to = body.assigned_to
    if body.notes is not None:
        inc.notes = body.notes

    db.commit()
    db.refresh(inc)
    return _inc_to_dict(inc)


@router.get("/stats/summary")
def incident_stats(db: Session = Depends(get_db)):
    """Return counts grouped by status and severity."""
    from sqlalchemy import func

    by_status = (
        db.query(Incident.status, func.count())
        .group_by(Incident.status)
        .all()
    )
    by_severity = (
        db.query(Incident.severity, func.count())
        .group_by(Incident.severity)
        .all()
    )
    return {
        "by_status": {s.value: c for s, c in by_status},
        "by_severity": {s.value: c for s, c in by_severity},
        "total": sum(c for _, c in by_status),
    }


# ── Helpers ───────────────────────────────────────────────────────────────

def _inc_to_dict(i: Incident) -> dict:
    rule = i.rule
    # Extract MITRE info from the rule's JSON DSL if available
    mitre_tactic = None
    mitre_technique = None
    if rule and rule.rule_definition:
        defn = rule.rule_definition
        tactics = defn.get("mitre_tactics", []) if isinstance(defn, dict) else []
        techniques = defn.get("mitre_techniques", []) if isinstance(defn, dict) else []
        mitre_tactic = tactics[0] if tactics else None
        mitre_technique = techniques[0] if techniques else None
    return {
        "id": i.id,
        "rule_slug": rule.slug if rule else None,
        "rule_name": rule.name if rule else None,
        "severity": i.severity.value if i.severity else None,
        "user_id": i.user_id,
        "user_display_name": "",
        "description": i.description,
        "evidence": i.correlated_event_ids,
        "risk_score_contribution": i.risk_score_at_creation,
        "status": i.status.value if i.status else None,
        "assigned_to": i.assigned_to,
        "notes": i.notes,
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "created_at": i.created_at.isoformat() if i.created_at else None,
        "updated_at": i.updated_at.isoformat() if i.updated_at else None,
    }
