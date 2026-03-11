"""Microsoft Teams alert channel via incoming webhook."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.alerting.base import BaseAlerter
from app.config import get_settings
from app.models.database import AlertChannel, Incident

logger = logging.getLogger(__name__)


class TeamsAlerter(BaseAlerter):
    """Post adaptive-card alerts to a Teams incoming webhook."""

    @property
    def channel(self) -> AlertChannel:
        return AlertChannel.TEAMS

    async def send(self, incident: Incident, context: dict[str, Any] | None = None) -> bool:
        settings = get_settings()
        if not settings.teams_alerting_enabled:
            logger.debug("Teams alerting disabled — skipping")
            return False

        webhook_url = settings.teams_webhook_url
        if not webhook_url:
            logger.warning("Teams webhook URL not configured")
            return False

        info = self.format_incident(incident)
        payload = _build_adaptive_card(info)

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(webhook_url, json=payload)
                resp.raise_for_status()
            logger.info("Teams alert sent for incident '%s'", info["title"])
            return True
        except Exception:
            logger.exception("Failed to send Teams alert for '%s'", info["title"])
            return False


def _severity_color(severity: str) -> str:
    return {
        "critical": "attention",
        "high": "warning",
        "medium": "accent",
        "low": "good",
        "info": "default",
    }.get(severity.lower(), "default")


def _build_adaptive_card(info: dict[str, str]) -> dict[str, Any]:
    color = _severity_color(info["severity"])
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "size": "Large",
                            "weight": "Bolder",
                            "text": f"🔔 {info['title']}",
                            "color": color,
                            "wrap": True,
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Severity", "value": info["severity"].upper()},
                                {"title": "User", "value": info["user"]},
                                {"title": "Risk Score", "value": info["risk_score"]},
                                {"title": "Status", "value": info["status"]},
                                {"title": "Created", "value": info["created_at"]},
                                {"title": "Rule", "value": info["rule_id"]},
                            ],
                        },
                    ],
                },
            }
        ],
    }
