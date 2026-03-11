"""Tests for the correlation rules engine."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.analyzers.rules_engine import (
    CorrelationRulesEngine,
    _compare,
    _resolve_field,
)
from app.models.database import (
    CorrelationRule,
    Incident,
    IncidentStatus,
    LogSource,
    Severity,
    SignInLog,
    UserWatchState,
)

from tests.conftest import make_correlation_rule, make_signin_log, make_watch_state


# ── Helper function tests ─────────────────────────────────────────────────


class TestResolveField:
    """Tests for _resolve_field helper."""

    def test_simple_attribute(self):
        log = make_signin_log(ip_address="10.0.0.1")
        assert _resolve_field(log, "ip_address") == "10.0.0.1"

    def test_nested_dict_via_raw_json(self):
        log = make_signin_log(raw_json={"nested": {"key": "value"}})
        assert _resolve_field(log, "raw_json.nested.key") == "value"

    def test_missing_field_returns_none(self):
        log = make_signin_log()
        assert _resolve_field(log, "nonexistent_field") is None

    def test_none_record(self):
        assert _resolve_field(None, "any.field") is None


class TestCompare:
    """Tests for _compare threshold helper."""

    def test_greater_than(self):
        from app.analyzers.rule_schema import FieldOperator
        assert _compare(10, FieldOperator.GREATER_THAN, 5) is True
        assert _compare(5, FieldOperator.GREATER_THAN, 10) is False

    def test_less_than(self):
        from app.analyzers.rule_schema import FieldOperator
        assert _compare(3, FieldOperator.LESS_THAN, 5) is True
        assert _compare(5, FieldOperator.LESS_THAN, 3) is False

    def test_equals(self):
        from app.analyzers.rule_schema import FieldOperator
        assert _compare(5, FieldOperator.EQUALS, 5) is True
        assert _compare(5, FieldOperator.EQUALS, 6) is False


# ── Engine tests ──────────────────────────────────────────────────────────


class TestCorrelationRulesEngine:
    """Tests for the core rules engine."""

    def _make_trigger_rule(self, db, slug="test-trigger", risk_match="high"):
        """Create a rule that triggers on high-risk sign-ins."""
        rule = CorrelationRule(
            slug=slug,
            name=f"Trigger on {risk_match} risk",
            severity=Severity.HIGH,
            risk_points=20,
            watch_window_days=14,
            rule_definition={
                "triggers": [
                    {
                        "source": "entra_signin",
                        "matchers": [
                            {
                                "field": "risk_level_during_sign_in",
                                "operator": "eq",
                                "value": risk_match,
                            }
                        ],
                    }
                ],
                "watch_window": {"enabled": True, "duration_days": 14, "risk_points": 20},
            },
            is_system=False,
            enabled=True,
        )
        db.add(rule)
        db.flush()
        return rule

    def test_no_rules_returns_empty(self, db):
        engine = CorrelationRulesEngine(db)
        record = make_signin_log()
        db.add(record)
        db.flush()

        incidents = engine.evaluate_new_logs([record], LogSource.ENTRA_SIGNIN)
        assert incidents == []

    def test_non_matching_record(self, db):
        self._make_trigger_rule(db, risk_match="high")
        record = make_signin_log(risk_level_during_sign_in="none")
        db.add(record)
        db.flush()

        engine = CorrelationRulesEngine(db)
        incidents = engine.evaluate_new_logs([record], LogSource.ENTRA_SIGNIN)
        assert incidents == []

    def test_matching_record_creates_incident(self, db):
        rule = self._make_trigger_rule(db, risk_match="high")
        record = make_signin_log(
            id="risky-signin-001",
            risk_level_during_sign_in="high",
            user_principal_name="alice@contoso.com",
        )
        db.add(record)
        db.flush()

        engine = CorrelationRulesEngine(db)
        incidents = engine.evaluate_new_logs([record], LogSource.ENTRA_SIGNIN)
        db.flush()

        assert len(incidents) == 1
        inc = incidents[0]
        assert inc.severity == Severity.HIGH
        assert inc.user_id == "alice@contoso.com"
        assert inc.rule_id == rule.id
        assert inc.status == IncidentStatus.OPEN

    def test_matching_record_opens_watch_window(self, db):
        self._make_trigger_rule(db, risk_match="high")
        record = make_signin_log(
            id="risky-002",
            risk_level_during_sign_in="high",
            user_principal_name="bob@contoso.com",
        )
        db.add(record)
        db.flush()

        engine = CorrelationRulesEngine(db)
        engine.evaluate_new_logs([record], LogSource.ENTRA_SIGNIN)
        db.flush()

        watches = db.query(UserWatchState).filter_by(user_id="bob@contoso.com").all()
        assert len(watches) == 1
        assert watches[0].is_active is True
        assert watches[0].risk_contribution == 20

    def test_disabled_rule_skipped(self, db):
        rule = self._make_trigger_rule(db, risk_match="high")
        rule.enabled = False
        db.flush()

        record = make_signin_log(risk_level_during_sign_in="high")
        db.add(record)
        db.flush()

        engine = CorrelationRulesEngine(db)
        incidents = engine.evaluate_new_logs([record], LogSource.ENTRA_SIGNIN)
        assert incidents == []

    def test_expire_watch_windows(self, db):
        rule = make_correlation_rule(slug="exp-rule", name="Expiring Rule")
        db.add(rule)
        db.flush()

        past = datetime.now(timezone.utc) - timedelta(days=1)
        ws = make_watch_state(
            rule,
            user_id="user@test.com",
            window_start=past - timedelta(days=14),
            window_end=past,
            is_active=True,
        )
        db.add(ws)
        db.flush()

        engine = CorrelationRulesEngine(db)
        expired = engine.expire_watch_windows()
        db.flush()

        assert expired == 1
        db.refresh(ws)
        assert ws.is_active is False

    def test_expire_no_expired_windows(self, db):
        rule = make_correlation_rule(slug="active-rule", name="Active Rule")
        db.add(rule)
        db.flush()

        future = datetime.now(timezone.utc) + timedelta(days=7)
        ws = make_watch_state(
            rule,
            user_id="user@test.com",
            window_end=future,
            is_active=True,
        )
        db.add(ws)
        db.flush()

        engine = CorrelationRulesEngine(db)
        expired = engine.expire_watch_windows()
        assert expired == 0

    def test_meta_rule_fires_with_enough_windows(self, db):
        """Meta-rule should fire when a user has enough active watch windows."""
        r1 = make_correlation_rule(slug="meta-pre-1", name="Meta Pre 1", risk_points=10)
        r2 = make_correlation_rule(slug="meta-pre-2", name="Meta Pre 2", risk_points=10)
        db.add_all([r1, r2])
        db.flush()

        # Create active watch windows for a user
        db.add(make_watch_state(r1, user_id="multi@test.com", risk_contribution=10))
        db.add(make_watch_state(r2, user_id="multi@test.com", risk_contribution=10))
        db.flush()

        # Meta-rule definition
        meta_rule = CorrelationRule(
            slug="meta-test",
            name="Meta Test Rule",
            severity=Severity.CRITICAL,
            risk_points=30,
            watch_window_days=0,
            rule_definition={
                "triggers": [],
                "meta_rule": {
                    "required_rule_slugs": ["meta-pre-1", "meta-pre-2"],
                    "min_active_windows": 2,
                },
                "watch_window": {"enabled": False, "duration_days": 1, "risk_points": 0},
            },
            is_system=True,
            enabled=True,
        )
        db.add(meta_rule)
        db.flush()

        engine = CorrelationRulesEngine(db)
        incidents = engine.evaluate_meta_rules()
        db.flush()

        assert len(incidents) == 1
        assert incidents[0].severity == Severity.CRITICAL
        assert incidents[0].user_id == "multi@test.com"

    def test_meta_rule_no_fire_insufficient_windows(self, db):
        """Meta-rule must not fire if the user doesn't have enough windows."""
        r1 = make_correlation_rule(slug="meta-solo", name="Meta Solo")
        db.add(r1)
        db.flush()

        db.add(make_watch_state(r1, user_id="solo@test.com"))
        db.flush()

        meta_rule = CorrelationRule(
            slug="meta-need-2",
            name="Meta Needs 2",
            severity=Severity.CRITICAL,
            risk_points=30,
            watch_window_days=0,
            rule_definition={
                "triggers": [],
                "meta_rule": {
                    "required_rule_slugs": ["meta-solo", "meta-solo-2"],
                    "min_active_windows": 2,
                },
                "watch_window": {"enabled": False, "duration_days": 1, "risk_points": 0},
            },
            enabled=True,
            is_system=True,
        )
        db.add(meta_rule)
        db.flush()

        engine = CorrelationRulesEngine(db)
        incidents = engine.evaluate_meta_rules()
        assert incidents == []


class TestFieldMatching:
    """Tests for the field matching logic within the engine."""

    def test_equals_match(self):
        from app.analyzers.rule_schema import FieldMatcher, FieldOperator
        record = make_signin_log(ip_address="10.0.0.1")
        matcher = FieldMatcher(field="ip_address", operator=FieldOperator.EQUALS, value="10.0.0.1")
        assert CorrelationRulesEngine._field_matches(record, matcher) is True

    def test_equals_no_match(self):
        from app.analyzers.rule_schema import FieldMatcher, FieldOperator
        record = make_signin_log(ip_address="10.0.0.2")
        matcher = FieldMatcher(field="ip_address", operator=FieldOperator.EQUALS, value="10.0.0.1")
        assert CorrelationRulesEngine._field_matches(record, matcher) is False

    def test_contains_match(self):
        from app.analyzers.rule_schema import FieldMatcher, FieldOperator
        record = make_signin_log(app_display_name="Microsoft Teams Desktop")
        matcher = FieldMatcher(field="app_display_name", operator=FieldOperator.CONTAINS, value="teams")
        assert CorrelationRulesEngine._field_matches(record, matcher) is True

    def test_in_operator(self):
        from app.analyzers.rule_schema import FieldMatcher, FieldOperator
        record = make_signin_log(risk_level_during_sign_in="high")
        matcher = FieldMatcher(
            field="risk_level_during_sign_in",
            operator=FieldOperator.IN,
            value=["high", "medium"],
        )
        assert CorrelationRulesEngine._field_matches(record, matcher) is True

    def test_exists_operator(self):
        from app.analyzers.rule_schema import FieldMatcher, FieldOperator
        record = make_signin_log(ip_address="1.2.3.4")
        matcher = FieldMatcher(field="ip_address", operator=FieldOperator.EXISTS)
        assert CorrelationRulesEngine._field_matches(record, matcher) is True

    def test_not_exists_operator(self):
        from app.analyzers.rule_schema import FieldMatcher, FieldOperator
        record = make_signin_log()
        matcher = FieldMatcher(field="nonexistent", operator=FieldOperator.NOT_EXISTS)
        assert CorrelationRulesEngine._field_matches(record, matcher) is True

    def test_regex_operator(self):
        from app.analyzers.rule_schema import FieldMatcher, FieldOperator
        record = make_signin_log(user_principal_name="admin@contoso.com")
        matcher = FieldMatcher(
            field="user_principal_name",
            operator=FieldOperator.REGEX,
            value=r"admin@.*\.com",
            case_insensitive=False,
        )
        assert CorrelationRulesEngine._field_matches(record, matcher) is True

    def test_greater_than_operator(self):
        from app.analyzers.rule_schema import FieldMatcher, FieldOperator
        record = make_signin_log(status_error_code=50125)
        matcher = FieldMatcher(
            field="status_error_code",
            operator=FieldOperator.GREATER_THAN,
            value=50000,
        )
        assert CorrelationRulesEngine._field_matches(record, matcher) is True
