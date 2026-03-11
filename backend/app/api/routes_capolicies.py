"""API routes for Conditional Access policy visualizer."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.auth.msal_client import TokenAcquisitionError, get_auth_client
from app.collectors.ca_policies import CAPolicyCollector, CAPolicyCollectorError
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


@router.get("/overlaps")
def policy_overlaps(
    db: Session = Depends(get_db),
    entity_type: str | None = None,
):
    """Return a graph data structure (nodes + links) for policy overlap visualization."""
    q = db.query(PolicyCoverageCache)
    if entity_type:
        q = q.filter(PolicyCoverageCache.entity_type == entity_type)
    entries = q.all()

    # Build policy nodes
    policy_ids = {e.policy_id for e in entries}
    policies = (
        db.query(ConditionalAccessPolicy)
        .filter(ConditionalAccessPolicy.id.in_(policy_ids))
        .all()
    ) if policy_ids else []
    policy_map = {p.id: p for p in policies}

    nodes: list[dict[str, Any]] = []
    links: list[dict[str, Any]] = []

    # Add policy nodes
    for p in policies:
        grant = p.grant_controls or {}
        nodes.append({
            "id": f"policy:{p.id}",
            "type": "policy",
            "label": p.display_name,
            "state": p.state,
            "grant_controls": grant.get("builtInControls", []),
        })

    # Group entries by entity to detect overlaps
    entity_policies: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in entries:
        key = f"{e.entity_type}:{e.entity_id}"
        entity_policies[key].append({
            "policy_id": e.policy_id,
            "inclusion_type": e.inclusion_type,
        })

    # Add entity nodes and links
    for key, pol_refs in entity_policies.items():
        etype, eid = key.split(":", 1)
        # Find display name from entries
        display_name = ""
        for e in entries:
            if e.entity_type == etype and e.entity_id == eid and e.entity_display_name:
                display_name = e.entity_display_name
                break

        nodes.append({
            "id": f"entity:{key}",
            "type": "entity",
            "entity_type": etype,
            "label": display_name or eid,
            "is_overlap": len({r["policy_id"] for r in pol_refs}) > 1,
            "policy_count": len({r["policy_id"] for r in pol_refs}),
        })

        for ref in pol_refs:
            links.append({
                "source": f"policy:{ref['policy_id']}",
                "target": f"entity:{key}",
                "inclusion_type": ref["inclusion_type"],
            })

    # Overlap summary: count of entities shared by 2+ policies, grouped by entity_type
    overlap_summary: dict[str, int] = defaultdict(int)
    for key, pol_refs in entity_policies.items():
        if len({r["policy_id"] for r in pol_refs}) > 1:
            etype = key.split(":", 1)[0]
            overlap_summary[etype] += 1

    return {
        "nodes": nodes,
        "links": links,
        "overlap_summary": dict(overlap_summary),
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


@router.get("/lookup")
def lookup_policies(
    db: Session = Depends(get_db),
    query: str = Query(..., min_length=1),
    entity_type: str | None = None,
):
    """Find all CA policies that apply to a given object (user, group, app, etc.).

    Searches the coverage cache by entity_id and entity_display_name,
    and also includes policies that target 'All' users/apps.
    """
    q = db.query(PolicyCoverageCache)
    if entity_type:
        q = q.filter(PolicyCoverageCache.entity_type == entity_type)

    # Search by exact entity_id or case-insensitive display name match
    search_pattern = f"%{query}%"
    direct_matches = q.filter(
        (PolicyCoverageCache.entity_id == query)
        | (PolicyCoverageCache.entity_display_name.ilike(search_pattern))
    ).all()

    # Also find "All" wildcard policies (target all users or all apps)
    wildcard_entries = (
        db.query(PolicyCoverageCache)
        .filter(PolicyCoverageCache.entity_id == "All")
        .all()
    )
    # If entity_type is specified, only include relevant wildcards
    if entity_type:
        wildcard_entries = [
            e for e in wildcard_entries
            if e.entity_type in ("user", "application")
        ]

    # Combine and deduplicate by (policy_id, entity_type, entity_id)
    seen: set[tuple[str, str, str]] = set()
    all_entries: list[PolicyCoverageCache] = []
    for e in direct_matches + wildcard_entries:
        key = (e.policy_id, e.entity_type, e.entity_id)
        if key not in seen:
            seen.add(key)
            all_entries.append(e)

    # Group by policy and enrich with full policy data
    policy_ids = {e.policy_id for e in all_entries}
    policies = (
        db.query(ConditionalAccessPolicy)
        .filter(ConditionalAccessPolicy.id.in_(policy_ids))
        .all()
    ) if policy_ids else []
    policy_map = {p.id: p for p in policies}

    results: list[dict[str, Any]] = []
    for pid in policy_ids:
        pol = policy_map.get(pid)
        if not pol:
            continue
        matching = [e for e in all_entries if e.policy_id == pid]
        results.append({
            "policy": _policy_to_dict(pol),
            "matches": [
                {
                    "entity_type": e.entity_type,
                    "entity_id": e.entity_id,
                    "entity_display_name": e.entity_display_name,
                    "inclusion_type": e.inclusion_type,
                    "is_wildcard": e.entity_id == "All",
                }
                for e in matching
            ],
        })

    return {
        "query": query,
        "entity_type": entity_type,
        "total_policies": len(results),
        "policies": results,
    }


@router.post("/lookup/resolve")
async def resolve_and_lookup(
    db: Session = Depends(get_db),
    query: str = Query(..., min_length=1),
    entity_type: str | None = None,
):
    """Resolve an object via live Graph API, then find applicable CA policies.

    Resolves user/group/app by ID or name, gets group memberships for users,
    and cross-references all resolved IDs against the coverage cache.
    """
    auth_client = get_auth_client()
    if not auth_client.is_configured:
        raise HTTPException(503, "MSAL client not configured")

    try:
        token = auth_client.get_graph_token()
    except TokenAcquisitionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    collector = CAPolicyCollector()

    resolved: dict[str, Any] | None = None
    resolved_ids: set[str] = set()
    resolved_type: str = ""

    try:
        if entity_type in (None, "user"):
            resolved = await collector.search_user(token, query)
            if resolved:
                resolved_type = "user"
                resolved_ids.add(resolved["id"])
                if resolved.get("userPrincipalName"):
                    resolved_ids.add(resolved["userPrincipalName"])
                # Also get group memberships
                group_ids = await collector.get_user_group_ids(token, resolved["id"])
                resolved_ids.update(group_ids)

        if not resolved and entity_type in (None, "group"):
            resolved = await collector.search_group(token, query)
            if resolved:
                resolved_type = "group"
                resolved_ids.add(resolved["id"])

        if not resolved and entity_type in (None, "application"):
            resolved = await collector.search_application(token, query)
            if resolved:
                resolved_type = "application"
                resolved_ids.add(resolved["id"])
                if resolved.get("appId"):
                    resolved_ids.add(resolved["appId"])
    finally:
        await collector.close()

    if not resolved:
        return {
            "query": query,
            "entity_type": entity_type,
            "resolved": None,
            "total_policies": 0,
            "policies": [],
        }

    # Search coverage cache for all resolved IDs + "All" wildcard
    matching_entries = (
        db.query(PolicyCoverageCache)
        .filter(
            (PolicyCoverageCache.entity_id.in_(resolved_ids))
            | (PolicyCoverageCache.entity_id == "All")
        )
        .all()
    )

    # Group by policy
    policy_ids = {e.policy_id for e in matching_entries}
    policies = (
        db.query(ConditionalAccessPolicy)
        .filter(ConditionalAccessPolicy.id.in_(policy_ids))
        .all()
    ) if policy_ids else []
    policy_map = {p.id: p for p in policies}

    results: list[dict[str, Any]] = []
    for pid in policy_ids:
        pol = policy_map.get(pid)
        if not pol:
            continue
        matching = [e for e in matching_entries if e.policy_id == pid]
        results.append({
            "policy": _policy_to_dict(pol),
            "matches": [
                {
                    "entity_type": e.entity_type,
                    "entity_id": e.entity_id,
                    "entity_display_name": e.entity_display_name,
                    "inclusion_type": e.inclusion_type,
                    "is_wildcard": e.entity_id == "All",
                }
                for e in matching
            ],
        })

    return {
        "query": query,
        "entity_type": entity_type,
        "resolved": {
            "type": resolved_type,
            "id": resolved.get("id"),
            "display_name": resolved.get("displayName", ""),
            "upn": resolved.get("userPrincipalName"),
            "app_id": resolved.get("appId"),
            "group_ids": list(resolved_ids - {resolved.get("id", ""), resolved.get("userPrincipalName", ""), resolved.get("appId", "")}),
        },
        "total_policies": len(results),
        "policies": results,
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

    try:
        token = auth_client.get_graph_token()
    except TokenAcquisitionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    collector = CAPolicyCollector()
    try:
        counts = await collector.sync_all(token, db)
    except CAPolicyCollectorError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
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
