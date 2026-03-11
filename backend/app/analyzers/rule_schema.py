"""Pydantic models defining the JSON DSL for correlation rules.

Every ``CorrelationRule.rule_definition`` column stores a JSON blob that
conforms to ``RuleDefinition``.  The engine deserialises the blob into this
model before evaluation, giving us type-safe access to trigger conditions,
field matchers, thresholds, time windows, and watch-window config.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────────────

class LogSourceFilter(str, Enum):
    ENTRA_SIGNIN = "entra_signin"
    ENTRA_AUDIT = "entra_audit"
    OFFICE365 = "office365"
    SHAREPOINT = "sharepoint"
    POWERAPPS = "powerapps"


class FieldOperator(str, Enum):
    EQUALS = "eq"
    NOT_EQUALS = "neq"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    IN = "in"
    NOT_IN = "not_in"
    REGEX = "regex"
    GREATER_THAN = "gt"
    LESS_THAN = "lt"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


class AggregationFunction(str, Enum):
    COUNT = "count"
    COUNT_DISTINCT = "count_distinct"
    SUM = "sum"
    AVG = "avg"
    MAX = "max"
    MIN = "min"


# ── Building blocks ───────────────────────────────────────────────────────

class FieldMatcher(BaseModel):
    """Match a single field on a log record."""

    field: str = Field(
        ..., description="Dot-path into the record, e.g. 'operation' or 'raw_json.riskLevelDuringSignIn'"
    )
    operator: FieldOperator
    value: Any = Field(
        None,
        description="Comparison value (not required for exists/not_exists)",
    )
    case_insensitive: bool = True


class TriggerCondition(BaseModel):
    """A set of field matchers all of which must match (AND semantics).

    Multiple ``TriggerCondition`` at the ``RuleDefinition`` level are OR-ed.
    """

    source: LogSourceFilter
    matchers: list[FieldMatcher] = Field(default_factory=list, min_length=1)


class ThresholdCondition(BaseModel):
    """Optional aggregation threshold – e.g. 'COUNT(*) > 10 within 1 h'."""

    aggregation: AggregationFunction = AggregationFunction.COUNT
    field: str | None = Field(None, description="Field for count_distinct / sum / etc.")
    operator: FieldOperator = FieldOperator.GREATER_THAN
    value: float = 1
    window_minutes: int = Field(60, ge=1, description="Sliding window in minutes")
    group_by: str = Field("user_id", description="Field to group aggregation by")


class CorrelationCondition(BaseModel):
    """Require *another* event within a time window of the trigger event.

    Used for multi-signal rules – e.g. 'MFA change followed by risky sign-in'.
    """

    secondary_source: LogSourceFilter
    secondary_matchers: list[FieldMatcher] = Field(default_factory=list, min_length=1)
    window_minutes: int = Field(
        1440,
        ge=1,
        description="How many minutes after the trigger to look for the secondary event",
    )
    direction: str = Field(
        "after",
        description="'before', 'after', or 'both' relative to trigger event",
    )


class WatchWindowConfig(BaseModel):
    """Configuration for placing a user under elevated monitoring."""

    enabled: bool = True
    duration_days: int = Field(14, ge=1, le=365)
    risk_points: int = Field(15, ge=0, le=100)


class MetaRuleCondition(BaseModel):
    """For meta-rules that fire when multiple watch windows are active.

    ``required_rules`` lists rule IDs (string slugs) that must all have active
    watch windows for the same user.
    """

    required_rule_slugs: list[str] = Field(
        default_factory=list, description="Rule slugs that must all be active (empty = any rules)"
    )
    min_active_windows: int = Field(
        2, ge=2, description="Minimum number of active watch windows"
    )


# ── Top-level definition ─────────────────────────────────────────────────

class RuleDefinition(BaseModel):
    """Complete rule definition stored as JSON in the database.

    Evaluation logic:
    1. For each incoming log record, check if *any* ``trigger`` matches (OR).
    2. If a ``threshold`` is defined, verify the aggregation condition.
    3. If ``correlations`` are defined, check each one.
    4. If all conditions pass → create incident and (optionally) open watch window.
    5. ``meta_rule`` conditions are evaluated separately against active watch states.
    """

    triggers: list[TriggerCondition] = Field(
        default_factory=list,
        description="One or more trigger conditions (OR-ed)",
    )
    threshold: ThresholdCondition | None = None
    correlations: list[CorrelationCondition] = Field(
        default_factory=list,
        description="Secondary events that must also occur (all must match = AND)",
    )
    watch_window: WatchWindowConfig = Field(default_factory=WatchWindowConfig)
    meta_rule: MetaRuleCondition | None = Field(
        None,
        description="If set, this is a meta-rule evaluated against active watch windows, not raw logs",
    )
    description: str = ""
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
