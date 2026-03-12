"""Correlation rule CRUD endpoints."""

from __future__ import annotations

import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.analyzers.rule_schema import RuleDefinition
from app.models.database import CorrelationRule, Severity, get_db

router = APIRouter(prefix="/api/rules", tags=["rules"])

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 200


def _clamp(limit: int) -> int:
    return max(1, min(limit, _MAX_LIMIT))


# ── Request schemas ───────────────────────────────────────────────────────

class RuleCreate(BaseModel):
    slug: str
    name: str
    description: str
    severity: str
    risk_points: int = 10
    watch_window_days: int = 0
    rule_json: dict
    enabled: bool = True

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        try:
            Severity(v)
        except ValueError:
            raise ValueError(f"Invalid severity: {v}")
        return v

    @field_validator("rule_json")
    @classmethod
    def validate_rule_json(cls, v: dict) -> dict:
        # Validate via Pydantic DSL model
        RuleDefinition.model_validate(v)
        return v


class RuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    risk_points: Optional[int] = None
    watch_window_days: Optional[int] = None
    rule_json: Optional[dict] = None
    enabled: Optional[bool] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                Severity(v)
            except ValueError:
                raise ValueError(f"Invalid severity: {v}")
        return v

    @field_validator("rule_json")
    @classmethod
    def validate_rule_json(cls, v: dict | None) -> dict | None:
        if v is not None:
            RuleDefinition.model_validate(v)
        return v


# ── Endpoints ─────────────────────────────────────────────────────────────

@router.get("")
def list_rules(
    db: Session = Depends(get_db),
    offset: int = Query(0, ge=0),
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    enabled_only: bool = False,
    category: Optional[str] = None,
):
    q = db.query(CorrelationRule)
    if enabled_only:
        q = q.filter(CorrelationRule.enabled.is_(True))
    if category:
        q = q.filter(CorrelationRule.slug.startswith(category))

    total = q.count()
    items = (
        q.order_by(CorrelationRule.slug)
        .offset(offset)
        .limit(_clamp(limit))
        .all()
    )
    return {"total": total, "offset": offset, "limit": _clamp(limit), "items": [_rule_to_dict(r) for r in items]}


@router.get("/{rule_id}")
def get_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(CorrelationRule).get(rule_id)
    if not rule:
        raise HTTPException(404, "Rule not found")
    return _rule_to_dict(rule)


@router.post("", status_code=201)
def create_rule(body: RuleCreate, db: Session = Depends(get_db)):
    existing = db.query(CorrelationRule).filter_by(slug=body.slug).first()
    if existing:
        raise HTTPException(409, f"Rule with slug '{body.slug}' already exists")

    rule = CorrelationRule(
        slug=body.slug,
        name=body.name,
        description=body.description,
        severity=Severity(body.severity),
        risk_points=body.risk_points,
        watch_window_days=body.watch_window_days,
        rule_definition=body.rule_json,
        enabled=body.enabled,
        is_system=False,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return _rule_to_dict(rule)


@router.patch("/{rule_id}")
def update_rule(rule_id: int, body: RuleUpdate, db: Session = Depends(get_db)):
    rule = db.query(CorrelationRule).get(rule_id)
    if not rule:
        raise HTTPException(404, "Rule not found")

    # System rules: only allow toggling enabled
    if rule.is_system:
        if body.enabled is not None:
            rule.enabled = body.enabled
        non_enabled_fields = {k: v for k, v in body.model_dump(exclude_unset=True).items() if k != "enabled"}
        if non_enabled_fields:
            raise HTTPException(403, "System rules can only be enabled/disabled, not modified")
        db.commit()
        db.refresh(rule)
        return _rule_to_dict(rule)

    if body.name is not None:
        rule.name = body.name
    if body.description is not None:
        rule.description = body.description
    if body.severity is not None:
        rule.severity = Severity(body.severity)
    if body.risk_points is not None:
        rule.risk_points = body.risk_points
    if body.watch_window_days is not None:
        rule.watch_window_days = body.watch_window_days
    if body.rule_json is not None:
        rule.rule_definition = body.rule_json
    if body.enabled is not None:
        rule.enabled = body.enabled

    db.commit()
    db.refresh(rule)
    return _rule_to_dict(rule)


@router.delete("/{rule_id}", status_code=204)
def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(CorrelationRule).get(rule_id)
    if not rule:
        raise HTTPException(404, "Rule not found")
    if rule.is_system:
        raise HTTPException(403, "System rules cannot be deleted — disable instead")
    db.delete(rule)
    db.commit()


# ── Helpers ───────────────────────────────────────────────────────────────

def _rule_to_dict(r: CorrelationRule) -> dict:
    defn = r.rule_definition or {}

    # Extract human-readable trigger summaries
    triggers_summary = []
    for t in defn.get("triggers", []):
        source = t.get("source", "?")
        matchers = t.get("matchers", [])
        parts = []
        for m in matchers:
            field = m.get("field", "")
            op = m.get("operator", "")
            val = m.get("value", "")
            if op == "in" and isinstance(val, list):
                val_str = ", ".join(str(v) for v in val[:5])
                if len(val) > 5:
                    val_str += f" (+{len(val) - 5} more)"
                parts.append(f"{field} IN [{val_str}]")
            elif op == "eq":
                parts.append(f"{field} = {val}")
            elif op == "contains":
                parts.append(f"{field} CONTAINS '{val}'")
            elif op == "exists":
                parts.append(f"{field} EXISTS")
            elif op == "not_exists":
                parts.append(f"{field} NOT EXISTS")
            elif op in ("gt", "lt", "neq", "not_contains", "not_in", "regex"):
                op_label = {"gt": ">", "lt": "<", "neq": "!=", "not_contains": "NOT CONTAINS", "not_in": "NOT IN", "regex": "REGEX"}.get(op, op)
                parts.append(f"{field} {op_label} {val}")
            else:
                parts.append(f"{field} {op} {val}")
        triggers_summary.append({"source": source, "conditions": parts})

    # Extract threshold summary
    threshold = defn.get("threshold")
    threshold_summary = None
    if threshold:
        agg = threshold.get("aggregation", "count").upper()
        op_map = {"gt": ">", "lt": "<", "eq": "=", "neq": "!="}
        op = op_map.get(threshold.get("operator", "gt"), threshold.get("operator", ">"))
        val = threshold.get("value", 0)
        window = threshold.get("window_minutes", 60)
        field = threshold.get("field")
        group = threshold.get("group_by", "user")
        agg_str = f"{agg}({field})" if field else agg
        threshold_summary = f"{agg_str} {op} {val} within {window} min (grouped by {group})"

    # Extract correlation summaries
    correlations_summary = []
    for c in defn.get("correlations", []):
        sec_source = c.get("secondary_source", "?")
        direction = c.get("direction", "after")
        window = c.get("window_minutes", 1440)
        sec_matchers = c.get("secondary_matchers", [])
        cond_parts = []
        for m in sec_matchers:
            f = m.get("field", "")
            o = m.get("operator", "")
            v = m.get("value", "")
            if o == "in" and isinstance(v, list):
                cond_parts.append(f"{f} IN [{', '.join(str(x) for x in v)}]")
            else:
                cond_parts.append(f"{f} {o} {v}")
        correlations_summary.append({
            "source": sec_source,
            "direction": direction,
            "window_minutes": window,
            "conditions": cond_parts,
        })

    # Watch window config
    ww = defn.get("watch_window", {})

    # MITRE
    mitre_tactics = defn.get("mitre_tactics", [])
    mitre_techniques = defn.get("mitre_techniques", [])

    # Is meta-rule?
    meta_rule = defn.get("meta_rule")
    meta_summary = None
    if meta_rule:
        required = meta_rule.get("required_rule_slugs", [])
        min_windows = meta_rule.get("min_active_windows", 2)
        meta_summary = {
            "required_rule_slugs": required,
            "min_active_windows": min_windows,
        }

    return {
        "id": r.id,
        "slug": r.slug,
        "name": r.name,
        "description": r.description or defn.get("description", ""),
        "category": r.category or "",
        "severity": r.severity.value if r.severity else None,
        "risk_points": r.risk_points,
        "watch_window_days": r.watch_window_days,
        "watch_window": {
            "enabled": ww.get("enabled", True),
            "duration_days": ww.get("duration_days", r.watch_window_days or 0),
            "risk_points": ww.get("risk_points", 0),
        },
        "triggers": triggers_summary,
        "threshold": threshold_summary,
        "correlations": correlations_summary,
        "meta_rule": meta_summary,
        "mitre_tactics": mitre_tactics,
        "mitre_techniques": mitre_techniques,
        "rule_json": r.rule_definition,
        "enabled": r.enabled,
        "is_system": r.is_system,
    }
