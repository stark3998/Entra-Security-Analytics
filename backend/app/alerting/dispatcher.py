"""Alert dispatcher – fans out incident alerts to all enabled channels.

Also records delivery status in ``AlertHistoryEntry``.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.alerting.base import BaseAlerter
from app.alerting.email_alert import EmailAlerter
from app.alerting.slack_alert import SlackAlerter
from app.alerting.teams_alert import TeamsAlerter
from app.models.database import (
    AlertDeliveryStatus,
    AlertHistoryEntry,
    Incident,
    Severity,
)

logger = logging.getLogger(__name__)

# Minimum severity to trigger alerts (configurable later)
DEFAULT_MIN_SEVERITY = Severity.MEDIUM

_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class AlertDispatcher:
    """Dispatch alerts for incidents across all configured channels."""

    def __init__(
        self,
        db: Session,
        min_severity: Severity = DEFAULT_MIN_SEVERITY,
    ) -> None:
        self._db = db
        self._min_severity = min_severity
        self._channels: list[BaseAlerter] = [
            EmailAlerter(),
            TeamsAlerter(),
            SlackAlerter(),
        ]

    async def dispatch(
        self,
        incidents: list[Incident],
        context: dict[str, Any] | None = None,
    ) -> int:
        """Send alerts for each incident that meets severity threshold.

        Returns total number of successful deliveries.
        """
        total_sent = 0
        for incident in incidents:
            if not self._meets_threshold(incident):
                continue
            sent = await self._dispatch_single(incident, context)
            total_sent += sent
        self._db.flush()
        return total_sent

    async def _dispatch_single(
        self,
        incident: Incident,
        context: dict[str, Any] | None,
    ) -> int:
        """Fan out a single incident to all channels concurrently."""
        tasks = [
            self._send_and_record(channel, incident, context)
            for channel in self._channels
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return sum(1 for r in results if r is True)

    async def _send_and_record(
        self,
        alerter: BaseAlerter,
        incident: Incident,
        context: dict[str, Any] | None,
    ) -> bool:
        try:
            ok = await alerter.send(incident, context)
        except Exception:
            logger.exception(
                "Unhandled error in %s alerter for '%s'",
                alerter.channel.value,
                incident.title,
            )
            ok = False

        entry = AlertHistoryEntry(
            incident_id=incident.id,
            channel=alerter.channel,
            status=AlertDeliveryStatus.SENT if ok else AlertDeliveryStatus.FAILED,
        )
        self._db.add(entry)
        return ok

    def _meets_threshold(self, incident: Incident) -> bool:
        inc_order = _SEVERITY_ORDER.get(incident.severity, 0)
        min_order = _SEVERITY_ORDER.get(self._min_severity, 0)
        return inc_order >= min_order
