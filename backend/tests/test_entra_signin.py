"""Tests for the Entra sign-in log collector."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.collectors.entra_signin import EntraSignInCollector, GRAPH_SIGNIN_URL
from app.models.database import SignInLog


# ── Fixtures ──────────────────────────────────────────────────────────────

SAMPLE_GRAPH_SIGNIN = {
    "id": "signin-graph-001",
    "userId": "aad-id-001",
    "userPrincipalName": "bob@contoso.com",
    "userDisplayName": "Bob Jones",
    "appId": "app-001",
    "appDisplayName": "Outlook",
    "ipAddress": "198.51.100.10",
    "clientAppUsed": "Browser",
    "isInteractive": True,
    "resourceDisplayName": "Microsoft Graph",
    "location": {
        "city": "Portland",
        "state": "OR",
        "countryOrRegion": "US",
        "geoCoordinates": {"latitude": 45.5, "longitude": -122.6},
    },
    "status": {"errorCode": 0, "failureReason": ""},
    "riskLevelDuringSignIn": "low",
    "riskLevelAggregated": "none",
    "riskState": "atRisk",
    "riskDetail": "",
    "riskEventTypes_v2": ["unfamiliarFeatures"],
    "conditionalAccessStatus": "success",
    "appliedConditionalAccessPolicies": [{"id": "p1"}],
    "mfaDetail": {"authMethod": "PhoneAppNotification"},
    "authenticationDetails": [{"authenticationMethod": "Password"}],
    "deviceDetail": {
        "deviceId": "dev-001",
        "operatingSystem": "Windows 11",
        "browser": "Edge 120",
    },
    "createdDateTime": "2024-06-15T10:30:00Z",
}


@pytest.fixture()
def collector(settings, mock_msal):
    with patch("app.config._settings", settings):
        c = EntraSignInCollector()
    return c


# ── Tests ─────────────────────────────────────────────────────────────────


class TestEntraSignInCollector:
    """Tests for EntraSignInCollector."""

    def test_collector_name(self, collector):
        assert collector.collector_name == "entra_signin"

    def test_normalize_single_record(self, collector):
        results = collector.normalize([SAMPLE_GRAPH_SIGNIN])
        assert len(results) == 1
        rec = results[0]

        assert isinstance(rec, SignInLog)
        assert rec.id == "signin-graph-001"
        assert rec.user_principal_name == "bob@contoso.com"
        assert rec.user_display_name == "Bob Jones"
        assert rec.ip_address == "198.51.100.10"
        assert rec.location_city == "Portland"
        assert rec.location_country == "US"
        assert rec.latitude == 45.5
        assert rec.status_error_code == 0
        assert rec.risk_level_during_sign_in == "low"
        assert rec.risk_state == "atRisk"
        assert rec.risk_event_types == ["unfamiliarFeatures"]
        assert rec.device_browser == "Edge 120"
        assert rec.device_os == "Windows 11"
        assert rec.created_date_time == datetime(2024, 6, 15, 10, 30, 0, tzinfo=timezone.utc)

    def test_normalize_empty_list(self, collector):
        assert collector.normalize([]) == []

    def test_normalize_missing_nested_fields(self, collector):
        """Records with missing optional nested dicts should not raise."""
        minimal = {
            "id": "signin-minimal",
            "userId": "uid",
            "userPrincipalName": "user@test.com",
            "createdDateTime": "2024-01-01T00:00:00Z",
        }
        results = collector.normalize([minimal])
        assert len(results) == 1
        rec = results[0]
        assert rec.location_city == ""
        assert rec.latitude is None
        assert rec.device_browser == ""

    def test_normalize_multiple_records(self, collector):
        rec2 = dict(SAMPLE_GRAPH_SIGNIN)
        rec2["id"] = "signin-graph-002"
        results = collector.normalize([SAMPLE_GRAPH_SIGNIN, rec2])
        assert len(results) == 2
        ids = {r.id for r in results}
        assert ids == {"signin-graph-001", "signin-graph-002"}

    @pytest.mark.asyncio
    async def test_fetch_page_builds_correct_url_params(self, collector, settings):
        """_fetch_page should send correct OData filter params."""
        since = datetime(2024, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        until = datetime(2024, 6, 15, 0, 0, 0, tzinfo=timezone.utc)

        mock_response = MagicMock()
        mock_response.json.return_value = {"value": [SAMPLE_GRAPH_SIGNIN]}

        with patch.object(collector, "_get", new_callable=AsyncMock, return_value=mock_response):
            records, next_link = await collector._fetch_page(
                token="fake-token", since=since, until=until
            )

        assert len(records) == 1
        assert records[0]["id"] == "signin-graph-001"
        assert next_link is None

    @pytest.mark.asyncio
    async def test_fetch_page_with_next_link(self, collector):
        """When a next_link is provided, use it directly."""
        next_url = "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skip=100"
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "value": [],
            "@odata.nextLink": None,
        }

        with patch.object(collector, "_get", new_callable=AsyncMock, return_value=mock_response) as mock_get:
            records, nl = await collector._fetch_page(
                token="fake-token",
                since=datetime.now(timezone.utc),
                until=datetime.now(timezone.utc),
                next_link=next_url,
            )

        mock_get.assert_called_once_with(next_url, "fake-token")
        assert records == []
