"""Statistical anomaly detection for user activity baselines.

Maintains per-user rolling baselines (daily counts) and flags deviations
exceeding a configurable Z-score threshold.  Uses ``scipy.stats.zscore``
when enough data points exist; otherwise falls back to simple comparisons.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from app.models.database import (
    AuditLog,
    Incident,
    IncidentStatus,
    LogSource,
    O365ActivityLog,
    Severity,
    SignInLog,
)

logger = logging.getLogger(__name__)

# Minimum historical data points before Z-score is meaningful
MIN_BASELINE_DAYS = 7
DEFAULT_Z_THRESHOLD = 3.0


class AnomalyDetector:
    """Detect statistical anomalies in per-user daily event counts."""

    def __init__(
        self,
        db: Session,
        z_threshold: float = DEFAULT_Z_THRESHOLD,
        baseline_days: int = 30,
    ) -> None:
        self._db = db
        self._z_threshold = z_threshold
        self._baseline_days = baseline_days

    def detect_all(self) -> list[Incident]:
        """Run anomaly detection across all log sources for today.

        Returns newly created ``Incident`` objects (already added to session).
        """
        today = datetime.now(timezone.utc).date()
        incidents: list[Incident] = []

        for source, model_cls, user_col, time_col in [
            (LogSource.ENTRA_SIGNIN, SignInLog, "user_principal_name", "created_date_time"),
            (LogSource.ENTRA_AUDIT, AuditLog, "initiated_by_user_upn", "activity_date_time"),
            (LogSource.OFFICE365, O365ActivityLog, "user_id", "creation_time"),
            (LogSource.SHAREPOINT, O365ActivityLog, "user_id", "creation_time"),
            (LogSource.POWERAPPS, O365ActivityLog, "user_id", "creation_time"),
        ]:
            source_filter = None
            if model_cls == O365ActivityLog:
                source_filter = source

            new = self._detect_for_source(
                model_cls, user_col, time_col, source, today, source_filter
            )
            incidents.extend(new)

        return incidents

    def _detect_for_source(
        self,
        model_cls: type,
        user_col: str,
        time_col: str,
        source: LogSource,
        today: Any,
        source_filter: LogSource | None,
    ) -> list[Incident]:
        """Compare today's per-user counts to historical baseline."""
        incidents: list[Incident] = []
        today_start = datetime.combine(today, datetime.min.time(), tzinfo=timezone.utc)
        today_end = today_start + timedelta(days=1)
        baseline_start = today_start - timedelta(days=self._baseline_days)

        # Build base filter for O365ActivityLog source column
        extra_filters: list[Any] = []
        if source_filter is not None:
            extra_filters.append(model_cls.source == source_filter)

        # Today's counts per user
        today_counts_q = (
            select(
                getattr(model_cls, user_col).label("user"),
                func.count().label("cnt"),
            )
            .where(
                and_(
                    getattr(model_cls, time_col) >= today_start,
                    getattr(model_cls, time_col) < today_end,
                    *extra_filters,
                )
            )
            .group_by(getattr(model_cls, user_col))
        )
        today_rows = self._db.execute(today_counts_q).all()

        if not today_rows:
            return incidents

        # Historical daily counts per user
        hist_q = (
            select(
                getattr(model_cls, user_col).label("user"),
                func.date(getattr(model_cls, time_col)).label("day"),
                func.count().label("cnt"),
            )
            .where(
                and_(
                    getattr(model_cls, time_col) >= baseline_start,
                    getattr(model_cls, time_col) < today_start,
                    *extra_filters,
                )
            )
            .group_by(
                getattr(model_cls, user_col),
                func.date(getattr(model_cls, time_col)),
            )
        )
        hist_rows = self._db.execute(hist_q).all()

        # Build per-user historical series
        user_history: dict[str, list[int]] = defaultdict(list)
        for row in hist_rows:
            user_history[row.user].append(row.cnt)

        for row in today_rows:
            user_id = row.user
            count_today = row.cnt
            history = user_history.get(user_id, [])

            if len(history) < MIN_BASELINE_DAYS:
                # Not enough data for statistical comparison; use simple 3x check
                avg = sum(history) / len(history) if history else 0
                if avg > 0 and count_today > avg * 3:
                    event_ids = self._fetch_today_event_ids(
                        model_cls, user_col, time_col, user_id,
                        today_start, today_end, extra_filters,
                    )
                    incident = self._create_anomaly_incident(
                        user_id, source, count_today, avg, 0.0,
                        len(history), event_ids,
                    )
                    incidents.append(incident)
                continue

            # Z-score calculation
            mean = sum(history) / len(history)
            variance = sum((x - mean) ** 2 for x in history) / len(history)
            std = variance ** 0.5

            if std == 0:
                if count_today > mean * 2:
                    event_ids = self._fetch_today_event_ids(
                        model_cls, user_col, time_col, user_id,
                        today_start, today_end, extra_filters,
                    )
                    incident = self._create_anomaly_incident(
                        user_id, source, count_today, mean, float("inf"),
                        len(history), event_ids,
                    )
                    incidents.append(incident)
                continue

            z_score = (count_today - mean) / std
            if z_score >= self._z_threshold:
                event_ids = self._fetch_today_event_ids(
                    model_cls, user_col, time_col, user_id,
                    today_start, today_end, extra_filters,
                )
                incident = self._create_anomaly_incident(
                    user_id, source, count_today, mean, z_score,
                    len(history), event_ids,
                )
                incidents.append(incident)

        return incidents

    def _fetch_today_event_ids(
        self,
        model_cls: type,
        user_col: str,
        time_col: str,
        user_id: str,
        today_start: datetime,
        today_end: datetime,
        extra_filters: list[Any],
        max_ids: int = 200,
    ) -> list[str]:
        """Fetch event IDs for today's activity that triggered the spike."""
        q = (
            select(model_cls.id)
            .where(
                and_(
                    getattr(model_cls, user_col) == user_id,
                    getattr(model_cls, time_col) >= today_start,
                    getattr(model_cls, time_col) < today_end,
                    *extra_filters,
                )
            )
            .order_by(getattr(model_cls, time_col).desc())
            .limit(max_ids)
        )
        rows = self._db.execute(q).scalars().all()
        return [str(eid) for eid in rows]

    def _create_anomaly_incident(
        self,
        user_id: str,
        source: LogSource,
        count_today: int,
        baseline_avg: float,
        z_score: float,
        baseline_days: int,
        event_ids: list[str],
    ) -> Incident:
        severity = Severity.MEDIUM if z_score < 5 else Severity.HIGH
        multiplier = round(count_today / baseline_avg, 1) if baseline_avg > 0 else 0
        risk_score = min(int(z_score * 5), 50) if z_score not in (0.0, float("inf")) else 30

        # Build a human-readable description
        source_label = source.value
        if z_score == 0.0:
            z_note = f"Insufficient baseline data ({baseline_days} days < {MIN_BASELINE_DAYS} required); using simple threshold (3× average)."
        elif z_score == float("inf"):
            z_note = "Zero variance in historical data — any increase is anomalous."
        else:
            z_note = f"Z-score: {z_score:.2f} (threshold: {self._z_threshold})."

        description = (
            f"Anomalous activity spike detected for user {user_id} "
            f"in {source_label} logs.\n\n"
            f"**Today's event count:** {count_today}\n"
            f"**Baseline average:** {baseline_avg:.1f} events/day "
            f"(over {baseline_days} day{'s' if baseline_days != 1 else ''} of history)\n"
            f"**Spike multiplier:** {multiplier}× the baseline average\n"
            f"**{z_note}**\n\n"
            f"**Evidence:** {len(event_ids)} event{'s' if len(event_ids) != 1 else ''} "
            f"collected from today's activity (showing up to 200 most recent). "
            f"Expand the evidence section to inspect individual events."
        )

        incident = Incident(
            title=f"Anomaly: {source_label} activity spike – {user_id}",
            description=description,
            severity=severity,
            status=IncidentStatus.OPEN,
            user_id=user_id,
            trigger_event_source=source_label,
            correlated_event_ids=event_ids,
            risk_score_at_creation=risk_score,
        )
        self._db.add(incident)
        logger.warning(
            "Anomaly detected: user=%s source=%s today=%d baseline_avg=%.1f z=%.2f events=%d",
            user_id,
            source.value,
            count_today,
            baseline_avg,
            z_score,
            len(event_ids),
        )
        return incident
