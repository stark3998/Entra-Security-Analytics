"""Collector for SharePoint audit logs via the O365 Management Activity API.

Uses content type Audit.SharePoint for file operations, sharing events, and admin actions.
"""

from __future__ import annotations

import httpx

from app.collectors.office365 import Office365Collector
from app.models.database import LogSource


class SharePointCollector(Office365Collector):
    """Fetches SharePoint audit logs (file operations, sharing, admin actions).

    Content type: Audit.SharePoint
    """

    def __init__(
        self,
        tenant_id: str,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(
            tenant_id=tenant_id,
            content_type="Audit.SharePoint",
            source=LogSource.SHAREPOINT,
            http_client=http_client,
        )

    @property
    def collector_name(self) -> str:
        return "sharepoint"
