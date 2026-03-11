"""Email alert channel via aiosmtplib."""

from __future__ import annotations

import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import aiosmtplib

from app.alerting.base import BaseAlerter
from app.config import get_settings
from app.models.database import AlertChannel, Incident

logger = logging.getLogger(__name__)


class EmailAlerter(BaseAlerter):
    """Send incident alerts via SMTP."""

    @property
    def channel(self) -> AlertChannel:
        return AlertChannel.EMAIL

    async def send(self, incident: Incident, context: dict[str, Any] | None = None) -> bool:
        settings = get_settings()
        if not settings.email_alerting_enabled:
            logger.debug("Email alerting disabled — skipping")
            return False

        recipients = settings.alert_email_recipients
        if not recipients:
            logger.warning("No email recipients configured")
            return False

        info = self.format_incident(incident)
        subject = f"[{info['severity'].upper()}] {info['title']}"
        body = _build_html_body(info)

        msg = MIMEMultipart("alternative")
        msg["From"] = settings.alert_email_from or settings.smtp_user or "loganalytics@noreply.local"
        msg["To"] = ", ".join(recipients)
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "html"))

        try:
            await aiosmtplib.send(
                msg,
                hostname=settings.smtp_host,
                port=settings.smtp_port,
                start_tls=settings.smtp_use_tls,
                username=settings.smtp_user or None,
                password=settings.smtp_password or None,
                timeout=15,
            )
            logger.info("Email alert sent for incident '%s' to %s", info["title"], recipients)
            return True
        except Exception:
            logger.exception("Failed to send email alert for '%s'", info["title"])
            return False


def _build_html_body(info: dict[str, str]) -> str:
    severity_colors = {
        "critical": "#d32f2f",
        "high": "#f57c00",
        "medium": "#fbc02d",
        "low": "#388e3c",
        "info": "#1976d2",
    }
    color = severity_colors.get(info["severity"].lower(), "#757575")

    return f"""\
<html>
<body style="font-family: Arial, sans-serif; color: #333;">
  <h2 style="color: {color};">🔔 {info['title']}</h2>
  <table style="border-collapse: collapse; width: 100%; max-width: 600px;">
    <tr><td style="padding:4px 8px; font-weight:bold;">Severity</td>
        <td style="padding:4px 8px; color:{color}; font-weight:bold;">{info['severity'].upper()}</td></tr>
    <tr><td style="padding:4px 8px; font-weight:bold;">User</td>
        <td style="padding:4px 8px;">{info['user']}</td></tr>
    <tr><td style="padding:4px 8px; font-weight:bold;">Risk Score</td>
        <td style="padding:4px 8px;">{info['risk_score']}</td></tr>
    <tr><td style="padding:4px 8px; font-weight:bold;">Status</td>
        <td style="padding:4px 8px;">{info['status']}</td></tr>
    <tr><td style="padding:4px 8px; font-weight:bold;">Created</td>
        <td style="padding:4px 8px;">{info['created_at']}</td></tr>
    <tr><td style="padding:4px 8px; font-weight:bold;">Rule</td>
        <td style="padding:4px 8px;">{info['rule_id']}</td></tr>
  </table>
  <p style="margin-top:16px; font-size:12px; color:#999;">
    Sent by Log Analytics SIEM-lite
  </p>
</body>
</html>"""
