"""Collector for Power Apps / Power Platform logs via the O365 Management Activity API.

Uses content type Audit.General and filters for Power Platform record types:
  - 45 (PowerAppsApp)
  - 30 (MicrosoftFlow / Power Automate)
  - 256 (PowerPlatformAdministratorActivity)
  - 187 (PowerPlatformAdminDlp)
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx

from app.collectors.office365 import Office365Collector
from app.models.database import LogSource, O365ActivityLog

logger = logging.getLogger(__name__)

POWER_PLATFORM_RECORD_TYPES = {30, 45, 46, 79, 186, 187, 256}


class PowerAppsCollector(Office365Collector):
    """Fetches Power Platform logs (Power Apps, Power Automate, admin activity).

    Content type: Audit.General (filtered to Power Platform record types).
    """

    def __init__(
        self,
        tenant_id: str,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(
            tenant_id=tenant_id,
            content_type="Audit.General",
            source=LogSource.POWERAPPS,
            http_client=http_client,
        )

    @property
    def collector_name(self) -> str:
        return "powerapps"

    def normalize(self, raw_records: list[dict[str, Any]]) -> list[O365ActivityLog]:
        """Filter to Power Platform records and normalize.

        Audit.General contains all workloads – we only keep Power Platform events.
        """
        power_records = [
            r
            for r in raw_records
            if r.get("RecordType") in POWER_PLATFORM_RECORD_TYPES
            or (r.get("Workload", "").lower() in ("powerapps", "microsoftflow", "powerplatform"))
        ]
        logger.info(
            "[%s] Filtered %d Power Platform records from %d total Audit.General records",
            self.collector_name,
            len(power_records),
            len(raw_records),
        )

        results: list[O365ActivityLog] = []
        for r in power_records:
            creation_time_str = r.get("CreationTime", "")
            if not creation_time_str:
                continue

            # Extract Power Platform-specific fields from nested PropertyCollection
            app_name = ""
            env_name = ""
            props = r.get("PropertyCollection", [])
            if isinstance(props, list):
                for p in props:
                    name = p.get("Name", "")
                    value = p.get("Value", "")
                    if "display_name" in name.lower() and "power_app" in name.lower():
                        app_name = value
                    elif "environment.name" in name.lower():
                        env_name = value

            cleaned_time = creation_time_str.replace("Z", "+00:00")
            results.append(
                O365ActivityLog(
                    id=r.get("Id", ""),
                    record_type=r.get("RecordType", 0),
                    creation_time=datetime.fromisoformat(cleaned_time),
                    operation=r.get("Operation", ""),
                    user_id=r.get("UserId", ""),
                    user_type=r.get("UserType", 0),
                    client_ip=r.get("ClientIP", ""),
                    workload=r.get("Workload", ""),
                    result_status=r.get("ResultStatus", ""),
                    object_id=r.get("ObjectId", ""),
                    source=LogSource.POWERAPPS,
                    app_name=app_name,
                    environment_name=env_name,
                    extended_properties=_extract_power_platform_props(r),
                    raw_json=r,
                )
            )
        return results


def _extract_power_platform_props(record: dict[str, Any]) -> dict[str, Any]:
    """Extract Power Platform-specific properties into a flat dict."""
    props: dict[str, Any] = {}
    for p in record.get("PropertyCollection", []):
        name = p.get("Name", "")
        if name:
            props[name] = p.get("Value", "")

    # Also include AppAccessContext if present
    app_ctx = record.get("AppAccessContext")
    if app_ctx:
        props["app_access_context"] = app_ctx

    return props
