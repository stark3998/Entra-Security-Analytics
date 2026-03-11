"""Collector for Microsoft Entra audit logs via Microsoft Graph API."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from app.collectors.base import BaseCollector
from app.models.database import AuditLog

logger = logging.getLogger(__name__)

GRAPH_AUDIT_URL = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"


class EntraAuditCollector(BaseCollector):
    """Fetches Entra audit logs from Microsoft Graph /auditLogs/directoryAudits."""

    @property
    def collector_name(self) -> str:
        return "entra_audit"

    async def _fetch_page(
        self,
        token: str,
        since: datetime,
        until: datetime,
        next_link: str | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        if next_link:
            resp = await self._get(next_link, token)
        else:
            since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
            until_str = until.strftime("%Y-%m-%dT%H:%M:%SZ")
            params = {
                "$filter": (
                    f"activityDateTime ge {since_str} and activityDateTime le {until_str}"
                ),
                "$orderby": "activityDateTime desc",
                "$top": "999",
            }
            resp = await self._get(GRAPH_AUDIT_URL, token, params)

        data = resp.json()
        records = data.get("value", [])
        next_page = data.get("@odata.nextLink")
        return records, next_page

    def normalize(self, raw_records: list[dict[str, Any]]) -> list[AuditLog]:
        """Convert raw Graph directoryAudit records into AuditLog model instances."""
        results: list[AuditLog] = []
        for r in raw_records:
            initiated_by = r.get("initiatedBy", {}) or {}
            user_info = initiated_by.get("user", {}) or {}
            app_info = initiated_by.get("app", {}) or {}

            results.append(
                AuditLog(
                    id=r.get("id", ""),
                    activity_display_name=r.get("activityDisplayName", ""),
                    activity_date_time=datetime.fromisoformat(
                        r["activityDateTime"].replace("Z", "+00:00")
                    ),
                    category=r.get("category", ""),
                    operation_type=r.get("operationType", ""),
                    result=r.get("result", ""),
                    result_reason=r.get("resultReason", ""),
                    logged_by_service=r.get("loggedByService", ""),
                    correlation_id=r.get("correlationId", ""),
                    initiated_by_user_id=user_info.get("id", ""),
                    initiated_by_user_upn=user_info.get("userPrincipalName", ""),
                    initiated_by_user_display_name=user_info.get("displayName", ""),
                    initiated_by_app_id=app_info.get("appId", ""),
                    initiated_by_app_display_name=app_info.get("displayName", ""),
                    target_resources=r.get("targetResources", []),
                    additional_details=r.get("additionalDetails", []),
                    raw_json=r,
                )
            )
        return results
