"""Collector for Microsoft Entra sign-in logs via Microsoft Graph API."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from app.collectors.base import BaseCollector
from app.models.database import SignInLog

logger = logging.getLogger(__name__)

GRAPH_SIGNIN_URL = "https://graph.microsoft.com/v1.0/auditLogs/signIns"


class EntraSignInCollector(BaseCollector):
    """Fetches Entra sign-in logs from Microsoft Graph /auditLogs/signIns."""

    @property
    def collector_name(self) -> str:
        return "entra_signin"

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
                    f"createdDateTime ge {since_str} and createdDateTime le {until_str}"
                ),
                "$orderby": "createdDateTime desc",
                "$top": "999",
            }
            resp = await self._get(GRAPH_SIGNIN_URL, token, params)

        data = resp.json()
        records = data.get("value", [])
        next_page = data.get("@odata.nextLink")
        return records, next_page

    def normalize(self, raw_records: list[dict[str, Any]]) -> list[SignInLog]:
        """Convert raw Graph signIn records into SignInLog model instances."""
        results: list[SignInLog] = []
        for r in raw_records:
            location = r.get("location", {}) or {}
            geo = location.get("geoCoordinates", {}) or {}
            status = r.get("status", {}) or {}
            device = r.get("deviceDetail", {}) or {}

            results.append(
                SignInLog(
                    id=r.get("id", ""),
                    user_id=r.get("userId", ""),
                    user_principal_name=r.get("userPrincipalName", ""),
                    user_display_name=r.get("userDisplayName", ""),
                    app_id=r.get("appId", ""),
                    app_display_name=r.get("appDisplayName", ""),
                    ip_address=r.get("ipAddress", ""),
                    client_app_used=r.get("clientAppUsed", ""),
                    is_interactive=r.get("isInteractive", True),
                    resource_display_name=r.get("resourceDisplayName", ""),
                    location_city=location.get("city", ""),
                    location_state=location.get("state", ""),
                    location_country=location.get("countryOrRegion", ""),
                    latitude=geo.get("latitude"),
                    longitude=geo.get("longitude"),
                    status_error_code=status.get("errorCode", 0),
                    status_failure_reason=status.get("failureReason", ""),
                    risk_level_during_sign_in=r.get("riskLevelDuringSignIn", "none"),
                    risk_level_aggregated=r.get("riskLevelAggregated", "none"),
                    risk_state=r.get("riskState", "none"),
                    risk_detail=r.get("riskDetail", ""),
                    risk_event_types=r.get("riskEventTypes_v2", []),
                    conditional_access_status=r.get("conditionalAccessStatus", "notApplied"),
                    applied_ca_policies=r.get("appliedConditionalAccessPolicies", []),
                    mfa_detail=r.get("mfaDetail"),
                    authentication_details=r.get("authenticationDetails", []),
                    device_id=device.get("deviceId", ""),
                    device_os=device.get("operatingSystem", ""),
                    device_browser=device.get("browser", ""),
                    created_date_time=datetime.fromisoformat(
                        r["createdDateTime"].replace("Z", "+00:00")
                    ),
                    raw_json=r,
                )
            )
        return results
