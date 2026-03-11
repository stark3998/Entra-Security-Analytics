"""Collector for Office 365 activity logs via the O365 Management Activity API.

The O365 Management API uses a subscription + poll model:
1. Start a subscription for a content type (one-time setup).
2. Poll for available content blobs within a time range.
3. Fetch each content blob for the actual audit records.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx

from app.collectors.base import BaseCollector
from app.models.database import LogSource, O365ActivityLog

logger = logging.getLogger(__name__)

O365_MGMT_BASE = "https://manage.office.com/api/v1.0"


class Office365Collector(BaseCollector):
    """Fetches Office 365 audit logs (Exchange, general activity).

    Content types: Audit.Exchange, Audit.General, Audit.AzureActiveDirectory
    """

    def __init__(
        self,
        tenant_id: str,
        content_type: str = "Audit.General",
        source: LogSource = LogSource.OFFICE365,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(http_client)
        self._tenant_id = tenant_id
        self._content_type = content_type
        self._source = source

    @property
    def collector_name(self) -> str:
        return f"o365_{self._content_type.lower().replace('.', '_')}"

    # ── Subscription management ────────────────────────────────

    async def ensure_subscription(self, token: str) -> None:
        """Start a subscription if not already active. Idempotent."""
        url = (
            f"{O365_MGMT_BASE}/{self._tenant_id}/activity/feed/subscriptions/start"
            f"?contentType={self._content_type}"
        )
        try:
            resp = await self._client.post(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                content="",
            )
            if resp.status_code in (200, 400):
                # 400 may mean already active – check response
                body = resp.json() if resp.content else {}
                if resp.status_code == 400:
                    error_code = body.get("error", {}).get("code", "")
                    if error_code == "AF20024":
                        logger.info(
                            "[%s] Subscription already active", self.collector_name
                        )
                        return
                    resp.raise_for_status()
                logger.info(
                    "[%s] Subscription started/confirmed", self.collector_name
                )
            else:
                resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            logger.error(
                "[%s] Failed to start subscription: %s",
                self.collector_name,
                exc.response.text,
            )
            raise

    # ── Content blob fetching ──────────────────────────────────

    async def _fetch_page(
        self,
        token: str,
        since: datetime,
        until: datetime,
        next_link: str | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Fetch content blobs and then fetch actual audit records from each blob."""
        if next_link:
            # next_link is a nextPageUri from the content listing
            resp = await self._get(next_link, token)
            data = resp.json() if isinstance(resp.json(), list) else []
            blobs = data if isinstance(data, list) else resp.json().get("value", [])
        else:
            since_str = since.strftime("%Y-%m-%dT%H:%M:%S")
            until_str = until.strftime("%Y-%m-%dT%H:%M:%S")
            url = (
                f"{O365_MGMT_BASE}/{self._tenant_id}/activity/feed/subscriptions/content"
                f"?contentType={self._content_type}"
                f"&startTime={since_str}&endTime={until_str}"
            )
            resp = await self._get(url, token)
            blobs = resp.json() if isinstance(resp.json(), list) else []

        # Get next page from header
        next_page = resp.headers.get("NextPageUri")

        # Fetch actual audit records from each content blob
        all_records: list[dict[str, Any]] = []
        for blob in blobs:
            content_uri = blob.get("contentUri", "")
            if content_uri:
                try:
                    blob_resp = await self._get(content_uri, token)
                    blob_data = blob_resp.json()
                    if isinstance(blob_data, list):
                        all_records.extend(blob_data)
                    else:
                        all_records.append(blob_data)
                except Exception:
                    logger.warning(
                        "[%s] Failed to fetch content blob: %s",
                        self.collector_name,
                        content_uri,
                        exc_info=True,
                    )

        return all_records, next_page

    # ── Normalization ──────────────────────────────────────────

    def normalize(self, raw_records: list[dict[str, Any]]) -> list[O365ActivityLog]:
        """Convert raw O365 Management API records into O365ActivityLog instances."""
        results: list[O365ActivityLog] = []
        for r in raw_records:
            creation_time_str = r.get("CreationTime", "")
            if not creation_time_str:
                continue

            results.append(
                O365ActivityLog(
                    id=r.get("Id", ""),
                    record_type=r.get("RecordType", 0),
                    creation_time=_parse_datetime(creation_time_str),
                    operation=r.get("Operation", ""),
                    user_id=r.get("UserId", ""),
                    user_type=r.get("UserType", 0),
                    client_ip=r.get("ClientIP", ""),
                    workload=r.get("Workload", ""),
                    result_status=r.get("ResultStatus", ""),
                    object_id=r.get("ObjectId", ""),
                    source=self._source,
                    site_url=r.get("SiteUrl", ""),
                    source_file_name=r.get("SourceFileName", ""),
                    source_file_extension=r.get("SourceFileExtension", ""),
                    source_relative_url=r.get("SourceRelativeUrl", ""),
                    item_type=r.get("ItemType", ""),
                    target_user_or_group_name=r.get("TargetUserOrGroupName", ""),
                    target_user_or_group_type=r.get("TargetUserOrGroupType", ""),
                    extended_properties=_extract_extended_properties(r),
                    raw_json=r,
                )
            )
        return results


def _parse_datetime(value: str) -> datetime:
    """Parse ISO datetime from O365 API (may or may not have timezone)."""
    cleaned = value.replace("Z", "+00:00")
    return datetime.fromisoformat(cleaned)


def _extract_extended_properties(record: dict[str, Any]) -> dict[str, Any]:
    """Extract non-standard properties into a flat dict for extended search."""
    props: dict[str, Any] = {}
    # ExtendedProperties is a list of {Name, Value} dicts
    for prop in record.get("ExtendedProperties", []):
        name = prop.get("Name", "")
        if name:
            props[name] = prop.get("Value", "")
    # AppAccessContext
    app_ctx = record.get("AppAccessContext")
    if app_ctx:
        props["app_access_context"] = app_ctx
    return props
