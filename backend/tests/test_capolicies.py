"""Tests for Conditional Access Policy visualizer (routes, collector, CLI)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tests.conftest import (
    make_auth_strength,
    make_ca_policy,
    make_coverage_entry,
    make_directory_group,
    make_named_location,
)


# ════════════════════════════════════════════════════════════════
#  API Route Tests
# ════════════════════════════════════════════════════════════════


class TestListPolicies:
    """GET /api/ca-policies"""

    def test_empty(self, client):
        resp = client.get("/api/ca-policies")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0
        assert body["items"] == []

    def test_returns_policies(self, client, db):
        db.add(make_ca_policy(id="p1", display_name="Policy A"))
        db.add(make_ca_policy(id="p2", display_name="Policy B", state="disabled"))
        db.commit()

        resp = client.get("/api/ca-policies")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 2
        assert len(body["items"]) == 2

    def test_filter_by_state(self, client, db):
        db.add(make_ca_policy(id="p1", state="enabled"))
        db.add(make_ca_policy(id="p2", state="disabled"))
        db.commit()

        resp = client.get("/api/ca-policies?state=enabled")
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["state"] == "enabled"


class TestGetPolicy:
    """GET /api/ca-policies/{policy_id}"""

    def test_not_found(self, client):
        resp = client.get("/api/ca-policies/nonexistent")
        assert resp.status_code == 404

    def test_found_with_coverage(self, client, db):
        pol = make_ca_policy(id="p1")
        db.add(pol)
        db.flush()
        db.add(make_coverage_entry(policy=pol, entity_type="user", entity_id="All"))
        db.commit()

        resp = client.get("/api/ca-policies/p1")
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == "p1"
        assert len(body["coverage"]) == 1
        assert body["coverage"][0]["entity_type"] == "user"


class TestPolicyStats:
    """GET /api/ca-policies/stats"""

    def test_empty(self, client):
        resp = client.get("/api/ca-policies/stats")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_policies"] == 0

    def test_counts(self, client, db):
        db.add(make_ca_policy(id="p1", state="enabled"))
        db.add(make_ca_policy(id="p2", state="disabled"))
        db.add(make_named_location())
        db.add(make_auth_strength())
        db.add(make_directory_group())
        db.commit()

        resp = client.get("/api/ca-policies/stats")
        body = resp.json()
        assert body["total_policies"] == 2
        assert body["by_state"]["enabled"] == 1
        assert body["by_state"]["disabled"] == 1
        assert body["named_locations"] == 1
        assert body["auth_strengths"] == 1
        assert body["directory_entries"] == 1


class TestCoverage:
    """GET /api/ca-policies/coverage"""

    def test_empty(self, client):
        resp = client.get("/api/ca-policies/coverage")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_entries"] == 0

    def test_groups_by_entity(self, client, db):
        pol = make_ca_policy(id="p1")
        db.add(pol)
        db.flush()
        db.add(make_coverage_entry(policy=pol, entity_type="user", entity_id="All"))
        db.add(
            make_coverage_entry(
                policy=pol, entity_type="application", entity_id="app-1"
            )
        )
        db.commit()

        resp = client.get("/api/ca-policies/coverage")
        body = resp.json()
        assert body["total_entries"] == 2
        assert len(body["by_entity"]) == 2
        assert len(body["by_policy"]) == 1

    def test_filter_by_entity_type(self, client, db):
        pol = make_ca_policy(id="p1")
        db.add(pol)
        db.flush()
        db.add(make_coverage_entry(policy=pol, entity_type="user", entity_id="All"))
        db.add(
            make_coverage_entry(
                policy=pol, entity_type="application", entity_id="app-1"
            )
        )
        db.commit()

        resp = client.get("/api/ca-policies/coverage?entity_type=user")
        body = resp.json()
        assert body["total_entries"] == 1


class TestCoverageGaps:
    """GET /api/ca-policies/coverage/gaps"""

    def test_empty(self, client):
        resp = client.get("/api/ca-policies/coverage/gaps")
        assert resp.status_code == 200
        assert resp.json()["total_gaps"] == 0

    def test_detects_issues(self, client, db):
        # Policy targeting all users with no exclusions, disabled, no platform
        db.add(
            make_ca_policy(
                id="p1",
                state="disabled",
                conditions={
                    "users": {"includeUsers": ["All"], "excludeUsers": []},
                    "applications": {"includeApplications": ["All"]},
                },
                grant_controls={"builtInControls": ["mfa"]},
            )
        )
        db.commit()

        resp = client.get("/api/ca-policies/coverage/gaps")
        body = resp.json()
        assert body["total_gaps"] == 1
        issues = body["gaps"][0]["issues"]
        assert any("all users" in i.lower() for i in issues)
        assert any("disabled" in i.lower() for i in issues)
        assert any("platform" in i.lower() for i in issues)


class TestCoverageSummary:
    """GET /api/ca-policies/coverage/summary"""

    def test_empty(self, client):
        resp = client.get("/api/ca-policies/coverage/summary")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_policies"] == 0

    def test_entity_coverage(self, client, db):
        pol = make_ca_policy(id="p1")
        db.add(pol)
        db.flush()
        db.add(
            make_coverage_entry(
                policy=pol,
                entity_type="user",
                entity_id="All",
                inclusion_type="include",
            )
        )
        db.commit()

        resp = client.get("/api/ca-policies/coverage/summary")
        body = resp.json()
        assert "user" in body["entity_coverage"]


class TestNamedLocations:
    """GET /api/ca-policies/named-locations"""

    def test_empty(self, client):
        resp = client.get("/api/ca-policies/named-locations")
        body = resp.json()
        assert body["total"] == 0

    def test_returns_locations(self, client, db):
        db.add(make_named_location(id="loc-1", display_name="HQ"))
        db.add(make_named_location(id="loc-2", display_name="Branch"))
        db.commit()

        resp = client.get("/api/ca-policies/named-locations")
        body = resp.json()
        assert body["total"] == 2


class TestAuthStrengths:
    """GET /api/ca-policies/auth-strengths"""

    def test_empty(self, client):
        resp = client.get("/api/ca-policies/auth-strengths")
        assert resp.json()["total"] == 0

    def test_returns_strengths(self, client, db):
        db.add(make_auth_strength(id="s-1", display_name="MFA"))
        db.commit()

        resp = client.get("/api/ca-policies/auth-strengths")
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["display_name"] == "MFA"


class TestDirectoryEntries:
    """GET /api/ca-policies/directory-entries"""

    def test_empty(self, client):
        resp = client.get("/api/ca-policies/directory-entries")
        assert resp.json()["total"] == 0

    def test_filter_by_type(self, client, db):
        db.add(make_directory_group(id="g1", object_type="group"))
        db.add(
            make_directory_group(
                id="r1", object_type="directoryRole", display_name="Global Admin"
            )
        )
        db.commit()

        resp = client.get("/api/ca-policies/directory-entries?object_type=group")
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["object_type"] == "group"


class TestSyncEndpoint:
    """POST /api/ca-policies/sync"""

    def test_sync_not_configured(self, client):
        """When MSAL is not configured, return 503."""
        with patch("app.api.routes_capolicies.get_auth_client") as mock_auth:
            mock_client = MagicMock()
            mock_client.is_configured = False
            mock_auth.return_value = mock_client

            resp = client.post("/api/ca-policies/sync")
            assert resp.status_code == 503

    def test_sync_success(self, client):
        """When sync succeeds, return counts."""
        with patch("app.api.routes_capolicies.get_auth_client") as mock_auth:
            mock_client = MagicMock()
            mock_client.is_configured = True
            mock_client.get_graph_token.return_value = "fake-token"
            mock_auth.return_value = mock_client

            with patch("app.api.routes_capolicies.CAPolicyCollector") as mock_coll_cls:
                mock_collector = AsyncMock()
                mock_collector.sync_all.return_value = {
                    "policies": 5,
                    "named_locations": 3,
                    "auth_strengths": 2,
                    "directory_groups": 10,
                    "coverage_entries": 25,
                }
                mock_collector.close = AsyncMock()
                mock_coll_cls.return_value = mock_collector

                resp = client.post("/api/ca-policies/sync")
                assert resp.status_code == 200
                body = resp.json()
                assert body["status"] == "ok"
                assert body["synced"]["policies"] == 5


class TestOverlaps:
    """GET /api/ca-policies/overlaps"""

    def test_empty(self, client):
        resp = client.get("/api/ca-policies/overlaps")
        assert resp.status_code == 200
        body = resp.json()
        assert body["nodes"] == []
        assert body["links"] == []
        assert body["overlap_summary"] == {}

    def test_returns_graph_data(self, client, db):
        p1 = make_ca_policy(id="p1", display_name="Policy A")
        p2 = make_ca_policy(id="p2", display_name="Policy B")
        db.add_all([p1, p2])
        db.flush()
        # Both policies target "All" users — overlap
        db.add(make_coverage_entry(policy=p1, entity_type="user", entity_id="All"))
        db.add(make_coverage_entry(policy=p2, entity_type="user", entity_id="All"))
        # Only p1 targets app-1
        db.add(make_coverage_entry(policy=p1, entity_type="application", entity_id="app-1"))
        db.commit()

        resp = client.get("/api/ca-policies/overlaps")
        body = resp.json()
        # 2 policy nodes + 2 entity nodes
        assert len(body["nodes"]) == 4
        assert len(body["links"]) == 3
        # user:All should be an overlap
        user_node = next(n for n in body["nodes"] if n["id"] == "entity:user:All")
        assert user_node["is_overlap"] is True
        assert user_node["policy_count"] == 2
        # app node should not be an overlap
        app_node = next(n for n in body["nodes"] if n["id"] == "entity:application:app-1")
        assert app_node["is_overlap"] is False
        assert body["overlap_summary"] == {"user": 1}

    def test_filter_by_entity_type(self, client, db):
        p1 = make_ca_policy(id="p1")
        db.add(p1)
        db.flush()
        db.add(make_coverage_entry(policy=p1, entity_type="user", entity_id="All"))
        db.add(make_coverage_entry(policy=p1, entity_type="application", entity_id="app-1"))
        db.commit()

        resp = client.get("/api/ca-policies/overlaps?entity_type=user")
        body = resp.json()
        entity_nodes = [n for n in body["nodes"] if n["type"] == "entity"]
        assert len(entity_nodes) == 1
        assert entity_nodes[0]["entity_type"] == "user"


class TestLookup:
    """GET /api/ca-policies/lookup"""

    def test_no_results(self, client):
        resp = client.get("/api/ca-policies/lookup?query=nonexistent")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_policies"] == 0

    def test_finds_by_entity_id(self, client, db):
        p1 = make_ca_policy(id="p1", display_name="MFA Policy")
        db.add(p1)
        db.flush()
        db.add(make_coverage_entry(policy=p1, entity_type="user", entity_id="user-123"))
        db.commit()

        resp = client.get("/api/ca-policies/lookup?query=user-123")
        body = resp.json()
        assert body["total_policies"] >= 1
        policy_ids = [r["policy"]["id"] for r in body["policies"]]
        assert "p1" in policy_ids

    def test_includes_wildcard_policies(self, client, db):
        p1 = make_ca_policy(id="p1", display_name="All Users MFA")
        db.add(p1)
        db.flush()
        db.add(make_coverage_entry(policy=p1, entity_type="user", entity_id="All"))
        db.commit()

        resp = client.get("/api/ca-policies/lookup?query=some-specific-user")
        body = resp.json()
        # Should still find p1 because it targets "All"
        assert body["total_policies"] >= 1
        assert any(
            any(m["is_wildcard"] for m in r["matches"])
            for r in body["policies"]
        )

    def test_finds_by_display_name(self, client, db):
        p1 = make_ca_policy(id="p1")
        db.add(p1)
        db.flush()
        db.add(
            make_coverage_entry(
                policy=p1,
                entity_type="group",
                entity_id="g-1",
                entity_display_name="Finance Team",
            )
        )
        db.commit()

        resp = client.get("/api/ca-policies/lookup?query=Finance")
        body = resp.json()
        assert body["total_policies"] >= 1

    def test_filter_by_entity_type(self, client, db):
        p1 = make_ca_policy(id="p1")
        db.add(p1)
        db.flush()
        db.add(make_coverage_entry(policy=p1, entity_type="user", entity_id="user-1"))
        db.add(make_coverage_entry(policy=p1, entity_type="application", entity_id="app-1"))
        db.commit()

        resp = client.get("/api/ca-policies/lookup?query=app-1&entity_type=application")
        body = resp.json()
        assert body["total_policies"] >= 1
        # All direct matches should be application type
        for r in body["policies"]:
            direct = [m for m in r["matches"] if not m["is_wildcard"]]
            for m in direct:
                assert m["entity_type"] == "application"


class TestResolveLookup:
    """POST /api/ca-policies/lookup/resolve"""

    def test_not_configured(self, client):
        """Returns 503 when MSAL not configured."""
        with patch("app.api.routes_capolicies.get_auth_client") as mock_auth:
            mock_client = MagicMock()
            mock_client.is_configured = False
            mock_auth.return_value = mock_client

            resp = client.post("/api/ca-policies/lookup/resolve?query=test")
            assert resp.status_code == 503

    def test_resolve_user(self, client, db):
        """Resolves a user and finds applicable policies."""
        p1 = make_ca_policy(id="p1")
        db.add(p1)
        db.flush()
        db.add(make_coverage_entry(policy=p1, entity_type="user", entity_id="All"))
        db.add(
            make_coverage_entry(
                policy=p1, entity_type="group", entity_id="group-abc"
            )
        )
        db.commit()

        with patch("app.api.routes_capolicies.get_auth_client") as mock_auth:
            mock_client = MagicMock()
            mock_client.is_configured = True
            mock_client.get_graph_token.return_value = "fake-token"
            mock_auth.return_value = mock_client

            with patch("app.api.routes_capolicies.CAPolicyCollector") as mock_coll_cls:
                mock_collector = AsyncMock()
                mock_collector.search_user.return_value = {
                    "id": "user-xyz",
                    "displayName": "Jane Doe",
                    "userPrincipalName": "jane@example.com",
                }
                mock_collector.get_user_group_ids.return_value = ["group-abc"]
                mock_collector.close = AsyncMock()
                mock_coll_cls.return_value = mock_collector

                resp = client.post(
                    "/api/ca-policies/lookup/resolve?query=jane@example.com&entity_type=user"
                )
                assert resp.status_code == 200
                body = resp.json()
                assert body["resolved"] is not None
                assert body["resolved"]["display_name"] == "Jane Doe"
                assert body["total_policies"] >= 1

    def test_resolve_not_found(self, client):
        """Returns empty when object cannot be resolved."""
        with patch("app.api.routes_capolicies.get_auth_client") as mock_auth:
            mock_client = MagicMock()
            mock_client.is_configured = True
            mock_client.get_graph_token.return_value = "fake-token"
            mock_auth.return_value = mock_client

            with patch("app.api.routes_capolicies.CAPolicyCollector") as mock_coll_cls:
                mock_collector = AsyncMock()
                mock_collector.search_user.return_value = None
                mock_collector.search_group.return_value = None
                mock_collector.search_application.return_value = None
                mock_collector.close = AsyncMock()
                mock_coll_cls.return_value = mock_collector

                resp = client.post(
                    "/api/ca-policies/lookup/resolve?query=unknown-entity"
                )
                assert resp.status_code == 200
                body = resp.json()
                assert body["resolved"] is None
                assert body["total_policies"] == 0


# ════════════════════════════════════════════════════════════════
#  Collector Unit Tests
# ════════════════════════════════════════════════════════════════


class TestCAPolicyCollectorNormalize:
    """Unit tests for the collector's normalization methods."""

    def test_normalize_policies(self):
        from app.collectors.ca_policies import CAPolicyCollector

        collector = CAPolicyCollector()
        raw = [
            {
                "id": "p1",
                "displayName": "Test Policy",
                "state": "enabled",
                "createdDateTime": "2024-03-01T12:00:00Z",
                "modifiedDateTime": "2024-06-01T12:00:00Z",
                "conditions": {"users": {"includeUsers": ["All"]}},
                "grantControls": {"builtInControls": ["mfa"]},
                "sessionControls": None,
            }
        ]
        result = collector.normalize_policies(raw)
        assert len(result) == 1
        assert result[0].id == "p1"
        assert result[0].display_name == "Test Policy"
        assert result[0].state == "enabled"
        assert result[0].conditions["users"]["includeUsers"] == ["All"]

    def test_normalize_locations_ip(self):
        from app.collectors.ca_policies import CAPolicyCollector

        collector = CAPolicyCollector()
        raw = [
            {
                "@odata.type": "#microsoft.graph.ipNamedLocation",
                "id": "loc-1",
                "displayName": "Office",
                "isTrusted": True,
                "ipRanges": [{"cidrAddress": "10.0.0.0/8"}],
            }
        ]
        result = collector.normalize_locations(raw)
        assert len(result) == 1
        assert result[0].location_type == "ipRange"
        assert result[0].is_trusted is True
        assert result[0].ip_ranges == ["10.0.0.0/8"]

    def test_normalize_locations_country(self):
        from app.collectors.ca_policies import CAPolicyCollector

        collector = CAPolicyCollector()
        raw = [
            {
                "@odata.type": "#microsoft.graph.countryNamedLocation",
                "id": "loc-2",
                "displayName": "Trusted Countries",
                "isTrusted": False,
                "countriesAndRegions": ["US", "GB"],
                "includeUnknownCountriesAndRegions": True,
            }
        ]
        result = collector.normalize_locations(raw)
        assert len(result) == 1
        assert result[0].location_type == "countryNamedLocation"
        assert result[0].countries_and_regions == ["US", "GB"]
        assert result[0].include_unknown_countries is True

    def test_normalize_auth_strengths(self):
        from app.collectors.ca_policies import CAPolicyCollector

        collector = CAPolicyCollector()
        raw = [
            {
                "id": "s1",
                "displayName": "MFA",
                "description": "Multi-factor",
                "policyType": "builtIn",
                "requirementsSatisfied": "mfa",
                "allowedCombinations": ["password,microsoftAuthenticatorPush"],
            }
        ]
        result = collector.normalize_auth_strengths(raw)
        assert len(result) == 1
        assert result[0].display_name == "MFA"
        assert result[0].requirements_satisfied == "mfa"

    def test_build_coverage_entries(self):
        from app.collectors.ca_policies import CAPolicyCollector

        collector = CAPolicyCollector()
        policy = make_ca_policy(
            id="p1",
            conditions={
                "users": {
                    "includeUsers": ["All"],
                    "excludeUsers": ["user-1"],
                    "includeGroups": ["group-1"],
                    "excludeGroups": [],
                    "includeRoles": [],
                    "excludeRoles": [],
                },
                "applications": {
                    "includeApplications": ["All"],
                    "excludeApplications": ["app-1"],
                },
            },
        )
        entries = collector.build_coverage_entries([policy])
        # Should have: include user All, exclude user user-1, include group group-1,
        # include app All, exclude app app-1
        assert len(entries) >= 4
        types = {(e.entity_type, e.inclusion_type, e.entity_id) for e in entries}
        assert ("user", "include", "All") in types
        assert ("user", "exclude", "user-1") in types
        assert ("group", "include", "group-1") in types
        assert ("application", "include", "All") in types
        assert ("application", "exclude", "app-1") in types
