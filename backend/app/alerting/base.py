"""Abstract base for alert channels."""

from __future__ import annotations

import abc
from typing import Any

from app.models.database import AlertChannel, Incident


class BaseAlerter(abc.ABC):
    """Interface that every alert channel must implement."""

    @property
    @abc.abstractmethod
    def channel(self) -> AlertChannel:
        """Return the channel enum value."""

    @abc.abstractmethod
    async def send(self, incident: Incident, context: dict[str, Any] | None = None) -> bool:
        """Deliver the alert.  Return True on success."""

    def format_incident(self, incident: Incident) -> dict[str, str]:
        """Build a human-readable summary dict."""
        return {
            "title": incident.title or "Unnamed Incident",
            "severity": incident.severity.value if incident.severity else "unknown",
            "status": incident.status.value if incident.status else "unknown",
            "user": incident.user_id or "N/A",
            "risk_score": str(incident.risk_score_at_creation or 0),
            "created_at": incident.created_at.isoformat() if incident.created_at else "",
            "rule_id": str(incident.rule_id) if incident.rule_id else "N/A",
        }
