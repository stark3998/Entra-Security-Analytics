"""API routes for Conditional Access policy visualizer."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.auth.msal_client import get_auth_client
from app.collectors.ca_policies import CAPolicyCollector
from app.models.database import (
    AuthenticationStrength,
    ConditionalAccessPolicy,
    DirectoryGroup,
    NamedLocation,
    PolicyCoverageCache,
    get_db,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ca-policies", tags=["ca-policies"])

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 200


def _clamp(limit: int) -> int:
    return max(1, min(limit, _MAX_LIMIT))


# ── Policy list / detail ──────────────────────────────────────


@router.get("")
def list_policies(
    db: Session = Depends(get_db),
    offset: int = Query(0, ge=0),
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    state: str | None = None,
):
    """List all cached conditional access policies."""
    q = db.query(ConditionalAccessPolicy)
    if state:
        q = q.filter(ConditionalAccessPolicy.state == state)

    total = q.count()
    items = (
        q.order_by(ConditionalAccessPolicy.display_name)
        .offset(offset)
        .limit(_clamp(limit))
        .all()
    )
    return {
        "total": total,
        "offset": offset,
        "limit": _clamp(limit),
        "items": [_policy_to_dict(p) for p in items],
    }


@router.get("/stats")
def policy_stats(db: Session = Depends(get_db)):
    """Aggregate statistics for CA policies."""
    total = db.query(func.count(ConditionalAccessPolicy.id)).scalar() or 0
    by_state = (
        db.query(ConditionalAccessPolicy.state, func.count())
        .group_by(ConditionalAccessPolicy.state)
        .all()
    )
    return {
        "total_policies": total,
        "by_state": {s: c for s, c in by_state},
        "named_locations": db.query(func.count(NamedLocation.id)).scalar() or 0,
        "auth_strengths": db.query(func.count(AuthenticationStrength.id)).scalar() or 0,
        "directory_entries": db.query(func.count(DirectoryGroup.id)).scalar() or 0,
    }


@router.get("/coverage")
def policy_coverage(
    db: Session = Depends(get_db),
    entity_type: str | None = None,
    policy_id: str | None = None,
):
    """Return the policy coverage map (which entities are covered by which policies)."""
    q = db.query(PolicyCoverageCache)
    if entity_type:
        q = q.filter(PolicyCoverageCache.entity_type == entity_type)
    if policy_id:
        q = q.filter(PolicyCoverageCache.policy_id == policy_id)

    entries = q.all()

    # Group entries by entity for easier frontend consumption
    by_entity: dict[str, dict[str, Any]] = {}
    for e in entries:
        key = f"{e.entity_type}:{e.entity_id}"
        if key not in by_entity:
            by_entity[key] = {
                "entity_type": e.entity_type,
                "entity_id": e.entity_id,
                "entity_display_name": e.entity_display_name,
                "policies": [],
            }
        by_entity[key]["policies"].append({
            "policy_id": e.policy_id,
            "inclusion_type": e.inclusion_type,
        })

    # Also group by policy for coverage summary
    by_policy: dict[str, dict[str, Any]] = {}
    for e in entries:
        if e.policy_id not in by_policy:
            by_policy[e.policy_id] = {
                "policy_id": e.policy_id,
                "entities": [],
            }
        by_policy[e.policy_id]["entities"].append({
            "entity_type": e.entity_type,
            "entity_id": e.entity_id,
            "entity_display_name": e.entity_display_name,
            "inclusion_type": e.inclusion_type,
        })

    return {
        "total_entries": len(entries),
        "by_entity": list(by_entity.values()),
        "by_policy": list(by_policy.values()),
    }


@router.get("/coverage/gaps")
def coverage_gaps(db: Session = Depends(get_db)):
    """Identify potential coverage gaps — policies with broad or missing targeting."""
    policies = db.query(ConditionalAccessPolicy).all()
    gaps: list[dict[str, Any]] = []

    for pol in policies:
        conditions = pol.conditions or {}
        issues: list[str] = []

        # Check for "All users" without exclusions
        users = conditions.get("users", {}) or {}
        if "All" in (users.get("includeUsers") or []) and not users.get("excludeUsers"):
            issues.append("Targets all users with no exclusions")

        # Check for missing application scope
        apps = conditions.get("applications", {}) or {}
        if not apps.get("includeApplications") and not apps.get("excludeApplications"):
            issues.append("No application conditions specified")

        # Check for disabled policies
        if pol.state == "disabled":
            issues.append("Policy is disabled")

        # Report-only policies
        if pol.state == "enabledForReportingButNotEnforced":
            issues.append("Policy is in report-only mode")

        # No grant controls
        grant = pol.grant_controls or {}
        if not grant.get("builtInControls") and not grant.get("authenticationStrength"):
            issues.append("No grant controls configured")

        # No platform conditions (applies to all platforms)
        if not conditions.get("platforms"):
            issues.append("No platform restrictions (applies to all platforms)")

        if issues:
            gaps.append({
                "policy_id": pol.id,
                "display_name": pol.display_name,
                "state": pol.state,
                "issues": issues,
            })

    return {"total_gaps": len(gaps), "gaps": gaps}


@router.get("/coverage/summary")
def coverage_summary(db: Session = Depends(get_db)):
    """High-level coverage summary: which entity types are covered and how much."""
    results = (
        db.query(
            PolicyCoverageCache.entity_type,
            PolicyCoverageCache.inclusion_type,
            func.count(func.distinct(PolicyCoverageCache.entity_id)),
        )
        .group_by(PolicyCoverageCache.entity_type, PolicyCoverageCache.inclusion_type)
        .all()
    )

    summary: dict[str, dict[str, int]] = defaultdict(lambda: {"included": 0, "excluded": 0})
    for entity_type, inclusion_type, count in results:
        summary[entity_type][inclusion_type + "d"] = count

    # Count policies by state
    policy_states = (
        db.query(ConditionalAccessPolicy.state, func.count())
        .group_by(ConditionalAccessPolicy.state)
        .all()
    )

    return {
        "entity_coverage": dict(summary),
        "policy_states": {s: c for s, c in policy_states},
        "total_policies": db.query(func.count(ConditionalAccessPolicy.id)).scalar() or 0,
    }


@router.get("/named-locations")
def list_named_locations(db: Session = Depends(get_db)):
    """List all cached named locations."""
    locations = db.query(NamedLocation).order_by(NamedLocation.display_name).all()
    return {
        "total": len(locations),
        "items": [_location_to_dict(loc) for loc in locations],
    }


@router.get("/auth-strengths")
def list_auth_strengths(db: Session = Depends(get_db)):
    """List all cached authentication strength policies."""
    strengths = db.query(AuthenticationStrength).order_by(AuthenticationStrength.display_name).all()
    return {
        "total": len(strengths),
        "items": [_auth_strength_to_dict(a) for a in strengths],
    }


@router.get("/directory-entries")
def list_directory_entries(
    db: Session = Depends(get_db),
    object_type: str | None = None,
):
    """List cached directory groups/roles."""
    q = db.query(DirectoryGroup)
    if object_type:
        q = q.filter(DirectoryGroup.object_type == object_type)
    entries = q.order_by(DirectoryGroup.display_name).all()
    return {
        "total": len(entries),
        "items": [_directory_entry_to_dict(e) for e in entries],
    }


@router.post("/sync", status_code=200)
async def sync_policies(db: Session = Depends(get_db)):
    """Trigger a full sync of CA policies and related data from Graph API."""
    auth_client = get_auth_client()
    if not auth_client.is_configured:
        raise HTTPException(
            status_code=503,
            detail="MSAL client not configured — set app registration credentials first",
        )

    token = auth_client.get_graph_token()
    collector = CAPolicyCollector()
    try:
        counts = await collector.sync_all(token, db)
    finally:
        await collector.close()

    return {"status": "ok", "synced": counts}


@router.get("/{policy_id}")
def get_policy(policy_id: str, db: Session = Depends(get_db)):
    """Return a single policy with full detail including coverage entries."""
    policy = db.get(ConditionalAccessPolicy, policy_id)
    if not policy:
        raise HTTPException(404, "Policy not found")

    coverage = (
        db.query(PolicyCoverageCache)
        .filter(PolicyCoverageCache.policy_id == policy_id)
        .all()
    )

    result = _policy_to_dict(policy)
    result["coverage"] = [
        {
            "entity_type": c.entity_type,
            "entity_id": c.entity_id,
            "entity_display_name": c.entity_display_name,
            "inclusion_type": c.inclusion_type,
        }
        for c in coverage
    ]
    return result


# ── Serialisation helpers ─────────────────────────────────────


def _policy_to_dict(p: ConditionalAccessPolicy) -> dict[str, Any]:
    return {
        "id": p.id,
        "display_name": p.display_name,
        "state": p.state,
        "created_date_time": p.created_date_time.isoformat() if p.created_date_time else None,
        "modified_date_time": p.modified_date_time.isoformat() if p.modified_date_time else None,
        "conditions": p.conditions,
        "grant_controls": p.grant_controls,
        "session_controls": p.session_controls,
    }


def _location_to_dict(loc: NamedLocation) -> dict[str, Any]:
    return {
        "id": loc.id,
        "display_name": loc.display_name,
        "is_trusted": loc.is_trusted,
        "location_type": loc.location_type,
        "ip_ranges": loc.ip_ranges,
        "countries_and_regions": loc.countries_and_regions,
        "include_unknown_countries": loc.include_unknown_countries,
    }


def _auth_strength_to_dict(a: AuthenticationStrength) -> dict[str, Any]:
    return {
        "id": a.id,
        "display_name": a.display_name,
        "description": a.description,
        "policy_type": a.policy_type,
        "requirements_satisfied": a.requirements_satisfied,
        "allowed_combinations": a.allowed_combinations,
    }


def _directory_entry_to_dict(e: DirectoryGroup) -> dict[str, Any]:
    return {
        "id": e.id,
        "display_name": e.display_name,
        "object_type": e.object_type,
        "description": e.description,
    }
