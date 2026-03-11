"""Tests for the FastAPI API routes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from app.models.database import (
    AuditLog,
    CorrelationRule,
    Incident,
    IncidentStatus,
    LogSource,
    O365ActivityLog,
    Severity,
    SignInLog,
    UserWatchState,
)

from tests.conftest import (
    make_activity_log,
    make_audit_log,
    make_correlation_rule,
    make_incident,
    make_signin_log,
    make_watch_state,
)


# ── Health ────────────────────────────────────────────────────────────────


class TestHealth:
    def test_health_endpoint(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


# ── Sign-in logs ──────────────────────────────────────────────────────────


class TestSignInLogRoutes:
    def _seed(self, client):
        """Insert test sign-in logs via the DB session."""
        from sqlalchemy.orm import Session, sessionmaker
        from app.models.database import get_db
        # Use the overridden db
        gen = client.app.dependency_overrides[get_db]()
        db = next(gen)
        db.add(make_signin_log(id="s1", user_principal_name="alice@test.com", risk_level_during_sign_in="none"))
        db.add(make_signin_log(id="s2", user_principal_name="bob@test.com", risk_level_during_sign_in="high"))
        db.commit()
        try:
            next(gen)
        except StopIteration:
            pass

    def test_list_signin_logs(self, client):
        self._seed(client)
        resp = client.get("/api/logs/signin")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2

    def test_filter_by_user(self, client):
        self._seed(client)
        resp = client.get("/api/logs/signin?user=alice")
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["user_principal_name"] == "alice@test.com"

    def test_filter_by_risk(self, client):
        self._seed(client)
        resp = client.get("/api/logs/signin?risk_level=high")
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["risk_level_during_signin"] == "high"

    def test_pagination(self, client):
        self._seed(client)
        resp = client.get("/api/logs/signin?limit=1&offset=0")
        data = resp.json()
        assert data["total"] == 2
        assert len(data["items"]) == 1

    def test_signin_dict_fields(self, client):
        self._seed(client)
        resp = client.get("/api/logs/signin?limit=1")
        item = resp.json()["items"][0]
        expected_keys = {
            "id", "user_display_name", "user_principal_name", "user_id",
            "app_display_name", "ip_address", "location_city", "location_country",
            "status_error_code", "status_failure_reason", "risk_level_during_signin",
            "risk_level_aggregated", "risk_state", "mfa_detail", "is_interactive",
            "conditional_access_status", "created_datetime",
        }
        assert expected_keys.issubset(set(item.keys()))


# ── Audit logs ────────────────────────────────────────────────────────────


class TestAuditLogRoutes:
    def _seed(self, client):
        from app.models.database import get_db
        gen = client.app.dependency_overrides[get_db]()
        db = next(gen)
        db.add(make_audit_log(id="a1", category="UserManagement", activity_display_name="Add user"))
        db.add(make_audit_log(id="a2", category="RoleManagement", activity_display_name="Add role member"))
        db.commit()
        try:
            next(gen)
        except StopIteration:
            pass

    def test_list_audit_logs(self, client):
        self._seed(client)
        resp = client.get("/api/logs/audit")
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

    def test_filter_by_category(self, client):
        self._seed(client)
        resp = client.get("/api/logs/audit?category=RoleManagement")
        assert resp.json()["total"] == 1

    def test_filter_by_activity(self, client):
        self._seed(client)
        resp = client.get("/api/logs/audit?activity=Add+role")
        data = resp.json()
        assert data["total"] == 1

    def test_audit_dict_fields(self, client):
        self._seed(client)
        item = client.get("/api/logs/audit?limit=1").json()["items"][0]
        expected_keys = {
            "id", "category", "activity_display_name", "activity_datetime",
            "result", "result_reason", "initiated_by_user", "initiated_by_app",
            "target_resources", "correlation_id",
        }
        assert expected_keys.issubset(set(item.keys()))


# ── Activity logs ─────────────────────────────────────────────────────────


class TestActivityLogRoutes:
    def _seed(self, client):
        from app.models.database import get_db
        gen = client.app.dependency_overrides[get_db]()
        db = next(gen)
        db.add(make_activity_log(id="act1", source=LogSource.SHAREPOINT, operation="FileAccessed"))
        db.add(make_activity_log(id="act2", source=LogSource.OFFICE365, operation="MailSend"))
        db.commit()
        try:
            next(gen)
        except StopIteration:
            pass

    def test_list_activity_logs(self, client):
        self._seed(client)
        resp = client.get("/api/logs/activity")
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

    def test_filter_by_source(self, client):
        self._seed(client)
        resp = client.get("/api/logs/activity?source=sharepoint")
        assert resp.json()["total"] == 1

    def test_filter_by_user(self, client):
        self._seed(client)
        resp = client.get("/api/logs/activity?user=alice")
        assert resp.json()["total"] == 2  # both have alice


# ── Incidents ─────────────────────────────────────────────────────────────


class TestIncidentRoutes:
    def _seed(self, client):
        from app.models.database import get_db
        gen = client.app.dependency_overrides[get_db]()
        db = next(gen)
        rule = make_correlation_rule(slug="inc-rule", name="Incident Rule")
        db.add(rule)
        db.flush()
        db.add(make_incident(rule, title="Inc A", severity=Severity.HIGH, status=IncidentStatus.OPEN))
        db.add(make_incident(rule, title="Inc B", severity=Severity.LOW, status=IncidentStatus.RESOLVED))
        db.commit()
        try:
            next(gen)
        except StopIteration:
            pass

    def test_list_incidents(self, client):
        self._seed(client)
        resp = client.get("/api/incidents")
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

    def test_filter_by_status(self, client):
        self._seed(client)
        resp = client.get("/api/incidents?status=open")
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["status"] == "open"

    def test_get_single_incident(self, client):
        self._seed(client)
        items = client.get("/api/incidents").json()["items"]
        inc_id = items[0]["id"]
        resp = client.get(f"/api/incidents/{inc_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == inc_id

    def test_get_nonexistent_returns_404(self, client):
        resp = client.get("/api/incidents/99999")
        assert resp.status_code == 404

    def test_patch_incident_status(self, client):
        self._seed(client)
        items = client.get("/api/incidents?status=open").json()["items"]
        inc_id = items[0]["id"]

        resp = client.patch(f"/api/incidents/{inc_id}", json={"status": "resolved"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "resolved"

    def test_patch_incident_invalid_status(self, client):
        self._seed(client)
        items = client.get("/api/incidents").json()["items"]
        inc_id = items[0]["id"]

        resp = client.patch(f"/api/incidents/{inc_id}", json={"status": "invalid_xyz"})
        assert resp.status_code == 400

    def test_incident_dict_has_expected_keys(self, client):
        self._seed(client)
        item = client.get("/api/incidents").json()["items"][0]
        expected_keys = {
            "id", "rule_slug", "rule_name", "severity", "user_id",
            "description", "evidence", "risk_score_contribution",
            "status", "assigned_to", "notes", "created_at", "updated_at",
        }
        assert expected_keys.issubset(set(item.keys()))

    def test_stats_summary(self, client):
        self._seed(client)
        resp = client.get("/api/incidents/stats/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "by_status" in data
        assert "by_severity" in data
        assert data["total"] == 2


# ── Rules ─────────────────────────────────────────────────────────────────


class TestRuleRoutes:
    def _seed(self, client):
        from app.models.database import get_db
        gen = client.app.dependency_overrides[get_db]()
        db = next(gen)
        db.add(make_correlation_rule(
            slug="sys-rule", name="System Rule", is_system=True,
        ))
        db.add(make_correlation_rule(
            slug="custom-rule", name="Custom Rule", is_system=False,
        ))
        db.commit()
        try:
            next(gen)
        except StopIteration:
            pass

    def test_list_rules(self, client):
        self._seed(client)
        resp = client.get("/api/rules")
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

    def test_get_single_rule(self, client):
        self._seed(client)
        items = client.get("/api/rules").json()["items"]
        rule_id = items[0]["id"]
        resp = client.get(f"/api/rules/{rule_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert "slug" in data
        assert "rule_json" in data

    def test_create_custom_rule(self, client):
        resp = client.post("/api/rules", json={
            "slug": "new-custom",
            "name": "New Custom Rule",
            "description": "A test rule",
            "severity": "high",
            "risk_points": 25,
            "watch_window_days": 7,
            "rule_json": {
                "triggers": [
                    {
                        "source": "entra_signin",
                        "matchers": [
                            {"field": "ip_address", "operator": "eq", "value": "10.0.0.1"}
                        ],
                    }
                ],
                "watch_window": {"enabled": False, "duration_days": 7, "risk_points": 10},
            },
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["slug"] == "new-custom"
        assert data["is_system"] is False

    def test_create_duplicate_slug_rejected(self, client):
        self._seed(client)
        resp = client.post("/api/rules", json={
            "slug": "sys-rule",
            "name": "Duplicate",
            "description": "",
            "severity": "low",
            "rule_json": {"triggers": [], "watch_window": {"enabled": False, "duration_days": 1, "risk_points": 0}},
        })
        assert resp.status_code == 409

    def test_toggle_system_rule(self, client):
        self._seed(client)
        items = client.get("/api/rules").json()["items"]
        sys_rule = next(r for r in items if r["is_system"])

        resp = client.patch(f"/api/rules/{sys_rule['id']}", json={"enabled": False})
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False

    def test_modify_system_rule_rejected(self, client):
        self._seed(client)
        items = client.get("/api/rules").json()["items"]
        sys_rule = next(r for r in items if r["is_system"])

        resp = client.patch(f"/api/rules/{sys_rule['id']}", json={"name": "Renamed"})
        assert resp.status_code == 403

    def test_delete_custom_rule(self, client):
        self._seed(client)
        items = client.get("/api/rules").json()["items"]
        custom = next(r for r in items if not r["is_system"])

        resp = client.delete(f"/api/rules/{custom['id']}")
        assert resp.status_code == 204

        resp2 = client.get(f"/api/rules/{custom['id']}")
        assert resp2.status_code == 404

    def test_delete_system_rule_rejected(self, client):
        self._seed(client)
        items = client.get("/api/rules").json()["items"]
        sys_rule = next(r for r in items if r["is_system"])

        resp = client.delete(f"/api/rules/{sys_rule['id']}")
        assert resp.status_code == 403


# ── Dashboard ─────────────────────────────────────────────────────────────


class TestDashboardRoutes:
    def _seed(self, client):
        from app.models.database import get_db
        gen = client.app.dependency_overrides[get_db]()
        db = next(gen)
        db.add(make_signin_log(id="dash-s1"))
        rule = make_correlation_rule(slug="dash-rule", name="Dashboard Rule")
        db.add(rule)
        db.flush()
        db.add(make_incident(rule, severity=Severity.CRITICAL))
        db.commit()
        try:
            next(gen)
        except StopIteration:
            pass

    def test_summary(self, client):
        self._seed(client)
        resp = client.get("/api/dashboard/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "open_incidents" in data
        assert "signin_events_24h" in data

    def test_risk_scores(self, client):
        resp = client.get("/api/dashboard/risk-scores")
        assert resp.status_code == 200
        assert "users" in resp.json()

    def test_incident_trend(self, client):
        resp = client.get("/api/dashboard/incident-trend?days=7")
        assert resp.status_code == 200
        data = resp.json()
        assert data["days"] == 7
        assert "trend" in data

    def test_log_volume(self, client):
        self._seed(client)
        resp = client.get("/api/dashboard/log-volume?days=7")
        assert resp.status_code == 200
        data = resp.json()
        assert "volumes" in data
        assert "entra_signin" in data["volumes"]

    def test_watched_users(self, client):
        resp = client.get("/api/dashboard/watched-users")
        assert resp.status_code == 200
        data = resp.json()
        assert "count" in data
        assert "users" in data
