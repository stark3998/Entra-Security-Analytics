"""Correlation rules engine – the heart of the SIEM-lite analyser.

Responsibilities:
  1. Evaluate incoming log batches against all enabled ``CorrelationRule`` rows.
  2. Check threshold / aggregation conditions over sliding windows.
  3. Validate secondary-event correlations.
  4. Evaluate meta-rules against active ``UserWatchState`` windows.
  5. Create ``Incident`` records and open / extend watch windows.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from app.analyzers.rule_schema import (
    AggregationFunction,
    CorrelationCondition,
    FieldMatcher,
    FieldOperator,
    LogSourceFilter,
    MetaRuleCondition,
    RuleDefinition,
    ThresholdCondition,
    TriggerCondition,
)
from app.models.database import (
    AuditLog,
    CorrelationRule,
    Incident,
    IncidentStatus,
    LogSource,
    O365ActivityLog,
    Severity,
    SignInLog,
    UserWatchState,
)

logger = logging.getLogger(__name__)

# Maps LogSourceFilter → (ORM model, user-field name, time-field name)
_SOURCE_MODEL_MAP: dict[LogSourceFilter, tuple[type, str, str]] = {
    LogSourceFilter.ENTRA_SIGNIN: (SignInLog, "user_principal_name", "created_date_time"),
    LogSourceFilter.ENTRA_AUDIT: (AuditLog, "initiated_by_user_upn", "activity_date_time"),
    LogSourceFilter.OFFICE365: (O365ActivityLog, "user_id", "creation_time"),
    LogSourceFilter.SHAREPOINT: (O365ActivityLog, "user_id", "creation_time"),
    LogSourceFilter.POWERAPPS: (O365ActivityLog, "user_id", "creation_time"),
}


class CorrelationRulesEngine:
    """Stateless rules engine that operates on a SQLAlchemy session."""

    def __init__(self, db: Session) -> None:
        self._db = db

    # ── Public API ────────────────────────────────────────────────────────

    def evaluate_new_logs(
        self,
        records: list[Any],
        source: LogSource,
    ) -> list[Incident]:
        """Evaluate a batch of *already-persisted* log records.

        Returns newly created ``Incident`` objects (already added to session).
        """
        rules = self._load_enabled_rules()
        incidents: list[Incident] = []

        for rule_row in rules:
            defn = RuleDefinition.model_validate(rule_row.rule_definition)

            # Skip meta-rules here – they are evaluated separately.
            if defn.meta_rule is not None:
                continue

            for record in records:
                if not self._any_trigger_matches(record, source, defn.triggers):
                    continue

                user_id = self._extract_user_id(record, source)
                if not user_id:
                    continue

                # Threshold check (optional)
                if defn.threshold and not self._check_threshold(
                    user_id, source, defn.threshold, record
                ):
                    continue

                # Correlation check (optional, all must match)
                if defn.correlations and not self._check_correlations(
                    user_id, record, defn.correlations
                ):
                    continue

                incident = self._create_incident(rule_row, defn, record, user_id, source)
                incidents.append(incident)

                if defn.watch_window.enabled:
                    self._open_watch_window(rule_row, defn, record, user_id, source)

        return incidents

    def evaluate_meta_rules(self) -> list[Incident]:
        """Evaluate meta-rules against currently active watch windows."""
        rules = self._load_enabled_rules()
        incidents: list[Incident] = []

        for rule_row in rules:
            defn = RuleDefinition.model_validate(rule_row.rule_definition)
            if defn.meta_rule is None:
                continue

            newly = self._evaluate_single_meta_rule(rule_row, defn, defn.meta_rule)
            incidents.extend(newly)

        return incidents

    def expire_watch_windows(self) -> int:
        """Deactivate watch windows whose ``window_end`` has passed."""
        now = datetime.now(timezone.utc)
        stmt = (
            select(UserWatchState)
            .where(
                and_(
                    UserWatchState.is_active == True,  # noqa: E712
                    UserWatchState.window_end <= now,
                )
            )
        )
        expired = self._db.execute(stmt).scalars().all()
        for ws in expired:
            ws.is_active = False
        self._db.flush()
        logger.info("Expired %d watch windows", len(expired))
        return len(expired)

    # ── Internal helpers ──────────────────────────────────────────────────

    def _load_enabled_rules(self) -> list[CorrelationRule]:
        stmt = select(CorrelationRule).where(CorrelationRule.enabled == True)  # noqa: E712
        return list(self._db.execute(stmt).scalars().all())

    # --- Trigger matching ------------------------------------------------

    def _any_trigger_matches(
        self,
        record: Any,
        source: LogSource,
        triggers: list[TriggerCondition],
    ) -> bool:
        source_filter = _log_source_to_filter(source)
        for trigger in triggers:
            if trigger.source != source_filter:
                continue
            if all(self._field_matches(record, m) for m in trigger.matchers):
                return True
        return False

    @staticmethod
    def _field_matches(record: Any, matcher: FieldMatcher) -> bool:
        """Evaluate a single ``FieldMatcher`` against a record."""
        actual = _resolve_field(record, matcher.field)
        expected = matcher.value
        op = matcher.operator

        # Normalise strings for case-insensitive comparison
        if matcher.case_insensitive and isinstance(actual, str):
            actual = actual.lower()
        if matcher.case_insensitive and isinstance(expected, str):
            expected = expected.lower()
        if matcher.case_insensitive and isinstance(expected, list):
            expected = [v.lower() if isinstance(v, str) else v for v in expected]

        if op == FieldOperator.EXISTS:
            return actual is not None
        if op == FieldOperator.NOT_EXISTS:
            return actual is None

        if actual is None:
            return False

        if op == FieldOperator.EQUALS:
            return actual == expected
        if op == FieldOperator.NOT_EQUALS:
            return actual != expected
        if op == FieldOperator.CONTAINS:
            return expected in actual if isinstance(actual, str) else False
        if op == FieldOperator.NOT_CONTAINS:
            return expected not in actual if isinstance(actual, str) else True
        if op == FieldOperator.IN:
            return actual in expected if isinstance(expected, list) else False
        if op == FieldOperator.NOT_IN:
            return actual not in expected if isinstance(expected, list) else True
        if op == FieldOperator.REGEX:
            return bool(re.search(expected, actual)) if isinstance(actual, str) else False
        if op == FieldOperator.GREATER_THAN:
            return float(actual) > float(expected)
        if op == FieldOperator.LESS_THAN:
            return float(actual) < float(expected)

        return False  # pragma: no cover

    # --- Threshold / aggregation -----------------------------------------

    def _check_threshold(
        self,
        user_id: str,
        source: LogSource,
        threshold: ThresholdCondition,
        record: Any,
    ) -> bool:
        source_filter = _log_source_to_filter(source)
        model_cls, user_col, time_col = _SOURCE_MODEL_MAP[source_filter]
        now = _record_time(record, source)
        window_start = now - timedelta(minutes=threshold.window_minutes)

        base_q = select(model_cls).where(
            and_(
                getattr(model_cls, user_col) == user_id,
                getattr(model_cls, time_col) >= window_start,
                getattr(model_cls, time_col) <= now,
            )
        )

        if threshold.aggregation == AggregationFunction.COUNT:
            count_q = select(func.count()).select_from(base_q.subquery())
            agg_value = self._db.execute(count_q).scalar() or 0
        elif threshold.aggregation == AggregationFunction.COUNT_DISTINCT:
            col = getattr(model_cls, threshold.field) if threshold.field else getattr(model_cls, "id")
            count_q = select(func.count(func.distinct(col))).where(
                and_(
                    getattr(model_cls, user_col) == user_id,
                    getattr(model_cls, time_col) >= window_start,
                    getattr(model_cls, time_col) <= now,
                )
            )
            agg_value = self._db.execute(count_q).scalar() or 0
        else:
            # SUM / AVG / MAX / MIN
            agg_fn = {
                AggregationFunction.SUM: func.sum,
                AggregationFunction.AVG: func.avg,
                AggregationFunction.MAX: func.max,
                AggregationFunction.MIN: func.min,
            }[threshold.aggregation]
            col = getattr(model_cls, threshold.field) if threshold.field else getattr(model_cls, "id")
            agg_q = select(agg_fn(col)).where(
                and_(
                    getattr(model_cls, user_col) == user_id,
                    getattr(model_cls, time_col) >= window_start,
                    getattr(model_cls, time_col) <= now,
                )
            )
            agg_value = self._db.execute(agg_q).scalar() or 0

        return _compare(agg_value, threshold.operator, threshold.value)

    # --- Correlation (secondary events) ----------------------------------

    def _check_correlations(
        self,
        user_id: str,
        trigger_record: Any,
        correlations: list[CorrelationCondition],
    ) -> bool:
        """All correlation conditions must be satisfied (AND)."""
        for corr in correlations:
            if not self._find_secondary_event(user_id, trigger_record, corr):
                return False
        return True

    def _find_secondary_event(
        self,
        user_id: str,
        trigger_record: Any,
        corr: CorrelationCondition,
    ) -> bool:
        model_cls, user_col, time_col = _SOURCE_MODEL_MAP[corr.secondary_source]

        # Determine search window based on direction
        trigger_source = _source_from_record(trigger_record)
        trigger_time = _record_time(trigger_record, trigger_source)
        window = timedelta(minutes=corr.window_minutes)

        time_filters = []
        if corr.direction in ("after", "both"):
            time_filters.append(getattr(model_cls, time_col) <= trigger_time + window)
        if corr.direction in ("before", "both"):
            time_filters.append(getattr(model_cls, time_col) >= trigger_time - window)
        if corr.direction == "after":
            time_filters.append(getattr(model_cls, time_col) >= trigger_time)
        if corr.direction == "before":
            time_filters.append(getattr(model_cls, time_col) <= trigger_time)

        base_q = select(model_cls).where(
            and_(
                getattr(model_cls, user_col) == user_id,
                *time_filters,
            )
        ).limit(500)

        candidates = self._db.execute(base_q).scalars().all()
        for candidate in candidates:
            if all(self._field_matches(candidate, m) for m in corr.secondary_matchers):
                return True
        return False

    # --- Meta-rule evaluation --------------------------------------------

    def _evaluate_single_meta_rule(
        self,
        rule_row: CorrelationRule,
        defn: RuleDefinition,
        meta: MetaRuleCondition,
    ) -> list[Incident]:
        """Find users with enough active watch windows to satisfy the meta-rule."""
        now = datetime.now(timezone.utc)
        incidents: list[Incident] = []

        # Build subquery: users with active windows matching required rule slugs
        active_windows = (
            self._db.execute(
                select(UserWatchState)
                .where(
                    and_(
                        UserWatchState.is_active == True,  # noqa: E712
                        UserWatchState.window_end > now,
                    )
                )
            )
            .scalars()
            .all()
        )

        # Group by user
        user_windows: dict[str, list[UserWatchState]] = {}
        for ws in active_windows:
            user_windows.setdefault(ws.user_id, []).append(ws)

        for uid, windows in user_windows.items():
            if len(windows) < meta.min_active_windows:
                continue

            # If specific rule slugs are required, check them
            if meta.required_rule_slugs:
                active_rule_ids = {ws.rule_id for ws in windows}
                # Resolve slugs to IDs
                slug_rules = self._db.execute(
                    select(CorrelationRule.id)
                    .where(CorrelationRule.slug.in_(meta.required_rule_slugs))
                ).scalars().all()
                required_ids = set(slug_rules)
                if not required_ids.issubset(active_rule_ids):
                    continue

            # Avoid duplicate meta-rule incidents for the same user within 24h
            recent = self._db.execute(
                select(Incident).where(
                    and_(
                        Incident.rule_id == rule_row.id,
                        Incident.user_id == uid,
                        Incident.created_at >= now - timedelta(hours=24),
                    )
                )
            ).scalars().first()
            if recent:
                continue

            incident = Incident(
                title=f"[Meta] {rule_row.name} – {uid}",
                severity=rule_row.severity,
                status=IncidentStatus.OPEN,
                rule_id=rule_row.id,
                user_id=uid,
                correlated_event_ids=[ws.trigger_event_id for ws in windows if ws.trigger_event_id],
                risk_score_at_creation=sum(ws.risk_contribution for ws in windows),
            )
            self._db.add(incident)
            incidents.append(incident)
            logger.warning(
                "Meta-rule '%s' fired for user %s (%d active windows)",
                rule_row.name,
                uid,
                len(windows),
            )

        return incidents

    # --- Incident / watch-window creation --------------------------------

    def _create_incident(
        self,
        rule_row: CorrelationRule,
        defn: RuleDefinition,
        record: Any,
        user_id: str,
        source: LogSource,
    ) -> Incident:
        event_id = getattr(record, "id", "")
        incident = Incident(
            title=f"{rule_row.name} – {user_id}",
            severity=rule_row.severity,
            status=IncidentStatus.OPEN,
            rule_id=rule_row.id,
            user_id=user_id,
            correlated_event_ids=[event_id] if event_id else [],
            risk_score_at_creation=rule_row.risk_points,
        )
        self._db.add(incident)
        logger.warning(
            "Rule '%s' fired for user %s (severity=%s, risk_points=%d)",
            rule_row.name,
            user_id,
            rule_row.severity.value,
            rule_row.risk_points,
        )
        return incident

    def _open_watch_window(
        self,
        rule_row: CorrelationRule,
        defn: RuleDefinition,
        record: Any,
        user_id: str,
        source: LogSource | None = None,
    ) -> UserWatchState:
        now = datetime.now(timezone.utc)
        duration = timedelta(days=defn.watch_window.duration_days)
        risk_pts = defn.watch_window.risk_points
        event_id = getattr(record, "id", "")

        # Check for an existing active window for same user+rule
        existing = self._db.execute(
            select(UserWatchState).where(
                and_(
                    UserWatchState.user_id == user_id,
                    UserWatchState.rule_id == rule_row.id,
                    UserWatchState.is_active == True,  # noqa: E712
                )
            )
        ).scalars().first()

        if existing:
            # Extend the window and bump risk contribution
            existing.window_end = max(existing.window_end, now + duration)
            existing.risk_contribution = min(100, existing.risk_contribution + risk_pts)
            logger.info(
                "Extended watch window for user %s / rule '%s' to %s",
                user_id,
                rule_row.name,
                existing.window_end.isoformat(),
            )
            return existing

        ws = UserWatchState(
            user_id=user_id,
            rule_id=rule_row.id,
            trigger_event_id=event_id,
            trigger_event_source=source.value if source else "unknown",
            window_start=now,
            window_end=now + duration,
            risk_contribution=risk_pts,
            is_active=True,
        )
        self._db.add(ws)
        logger.info(
            "Opened watch window for user %s / rule '%s' (%d days, %d pts)",
            user_id,
            rule_row.name,
            defn.watch_window.duration_days,
            risk_pts,
        )
        return ws

    # --- Field extraction helpers ----------------------------------------

    @staticmethod
    def _extract_user_id(record: Any, source: LogSource) -> str | None:
        source_filter = _log_source_to_filter(source)
        _, user_col, _ = _SOURCE_MODEL_MAP[source_filter]
        return getattr(record, user_col, None)


# ── Module-level helpers ──────────────────────────────────────────────────


def _log_source_to_filter(source: LogSource) -> LogSourceFilter:
    return {
        LogSource.ENTRA_SIGNIN: LogSourceFilter.ENTRA_SIGNIN,
        LogSource.ENTRA_AUDIT: LogSourceFilter.ENTRA_AUDIT,
        LogSource.OFFICE365: LogSourceFilter.OFFICE365,
        LogSource.SHAREPOINT: LogSourceFilter.SHAREPOINT,
        LogSource.POWERAPPS: LogSourceFilter.POWERAPPS,
    }[source]


def _source_from_record(record: Any) -> LogSource:
    """Infer LogSource from an ORM record instance."""
    if isinstance(record, SignInLog):
        return LogSource.ENTRA_SIGNIN
    if isinstance(record, AuditLog):
        return LogSource.ENTRA_AUDIT
    if isinstance(record, O365ActivityLog):
        return record.source  # type: ignore[return-value]
    raise ValueError(f"Cannot determine source for {type(record)}")  # pragma: no cover


def _record_time(record: Any, source: LogSource) -> datetime:
    source_filter = _log_source_to_filter(source)
    _, _, time_col = _SOURCE_MODEL_MAP[source_filter]
    ts = getattr(record, time_col)
    if ts and ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts


def _resolve_field(record: Any, field_path: str) -> Any:
    """Resolve a dot-separated field path on an ORM model.

    Supports traversal into ``raw_json`` dicts with paths like
    ``raw_json.riskLevelDuringSignIn``.
    """
    parts = field_path.split(".")
    current: Any = record
    for part in parts:
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(part)
        else:
            current = getattr(current, part, None)
    return current


def _compare(actual: float, operator: FieldOperator, expected: float) -> bool:
    if operator == FieldOperator.GREATER_THAN:
        return actual > expected
    if operator == FieldOperator.LESS_THAN:
        return actual < expected
    if operator == FieldOperator.EQUALS:
        return actual == expected
    if operator == FieldOperator.NOT_EQUALS:
        return actual != expected
    return False  # pragma: no cover
