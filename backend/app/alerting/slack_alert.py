"""Slack alert channel via incoming webhook."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.alerting.base import BaseAlerter
from app.config import get_settings
from app.models.database import AlertChannel, Incident

logger = logging.getLogger(__name__)


class SlackAlerter(BaseAlerter):
    """Post structured alerts to a Slack incoming webhook."""

    @property
    def channel(self) -> AlertChannel:
        return AlertChannel.SLACK

    async def send(self, incident: Incident, context: dict[str, Any] | None = None) -> bool:
        settings = get_settings()
        if not settings.slack_alerting_enabled:
            logger.debug("Slack alerting disabled — skipping")
            return False

        webhook_url = settings.slack_webhook_url
        if not webhook_url:
            logger.warning("Slack webhook URL not configured")
            return False

        info = self.format_incident(incident)
        payload = _build_slack_blocks(info)

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(webhook_url, json=payload)
                resp.raise_for_status()
            logger.info("Slack alert sent for incident '%s'", info["title"])
            return True
        except Exception:
            logger.exception("Failed to send Slack alert for '%s'", info["title"])
            return False


def _severity_emoji(severity: str) -> str:
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
        "info": "🔵",
    }.get(severity.lower(), "⚪")


def _build_slack_blocks(info: dict[str, str]) -> dict[str, Any]:
    emoji = _severity_emoji(info["severity"])
    return {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {info['title']}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:*\n{info['severity'].upper()}"},
                    {"type": "mrkdwn", "text": f"*User:*\n{info['user']}"},
                    {"type": "mrkdwn", "text": f"*Risk Score:*\n{info['risk_score']}"},
                    {"type": "mrkdwn", "text": f"*Status:*\n{info['status']}"},
                    {"type": "mrkdwn", "text": f"*Created:*\n{info['created_at']}"},
                    {"type": "mrkdwn", "text": f"*Rule:*\n{info['rule_id']}"},
                ],
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "Sent by Log Analytics SIEM-lite",
                    }
                ],
            },
        ],
    }
