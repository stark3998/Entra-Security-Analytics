"""Tests for the compounding risk scorer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.analyzers.risk_scorer import (
    ENTRA_RISK_MAP,
    MULTIPLIER_THRESHOLDS,
    RiskResult,
    RiskScorer,
)
from app.models.database import Severity

from tests.conftest import make_correlation_rule, make_signin_log, make_watch_state


class TestRiskResult:
    """Value object tests."""

    def test_to_dict(self):
        r = RiskResult(
            user_id="alice@contoso.com",
            score=42,
            base_risk=30,
            entra_risk=5,
            entra_risk_level="low",
            multiplier=1.25,
            active_windows=2,
            window_details=[],
        )
        d = r.to_dict()
        assert d["user_id"] == "alice@contoso.com"
        assert d["score"] == 42
        assert d["base_risk"] == 30
        assert d["multiplier"] == 1.25

    def test_repr(self):
        r = RiskResult(
            user_id="bob@test.com", score=80, base_risk=50, entra_risk=15,
            entra_risk_level="medium", multiplier=1.5, active_windows=3, window_details=[],
        )
        assert "bob@test.com" in repr(r)
        assert "80" in repr(r)


class TestEntraRiskMap:
    """Verify ENTRA_RISK_MAP values."""

    @pytest.mark.parametrize("level,expected", [
        (None, 0), ("none", 0), ("hidden", 0),
        ("low", 5), ("medium", 15), ("high", 30),
    ])
    def test_known_levels(self, level, expected):
        assert ENTRA_RISK_MAP[level] == expected

    def test_unknown_level_defaults_to_zero(self):
        assert ENTRA_RISK_MAP.get("unknown", 0) == 0


class TestRiskScorer:
    """Integration tests using an in-memory database."""

    def test_score_user_no_windows(self, db):
        scorer = RiskScorer(db)
        result = scorer.score_user("nobody@contoso.com")
        assert result.score == 0
        assert result.active_windows == 0
        assert result.base_risk == 0
        assert result.multiplier == 1.0

    def test_score_user_single_window(self, db):
        rule = make_correlation_rule(slug="r1", name="Rule 1")
        db.add(rule)
        db.flush()

        ws = make_watch_state(rule, user_id="alice@contoso.com", risk_contribution=20)
        db.add(ws)
        db.flush()

        scorer = RiskScorer(db)
        result = scorer.score_user("alice@contoso.com")

        assert result.base_risk == 20
        assert result.active_windows == 1
        assert result.multiplier == 1.0
        # No sign-in → entra_risk=0
        assert result.entra_risk == 0
        assert result.score == 20  # min(100, (20+0)*1.0)

    def test_score_user_with_entra_risk(self, db):
        rule = make_correlation_rule(slug="r2", name="Rule 2")
        db.add(rule)
        db.flush()

        ws = make_watch_state(rule, user_id="bob@contoso.com", risk_contribution=10)
        db.add(ws)
        signin = make_signin_log(
            id="s1",
            user_principal_name="bob@contoso.com",
            risk_level_during_sign_in="medium",
        )
        db.add(signin)
        db.flush()

        scorer = RiskScorer(db)
        result = scorer.score_user("bob@contoso.com")

        assert result.entra_risk == 15  # medium
        assert result.score == 25  # min(100, (10+15)*1.0)

    def test_multiplier_two_windows(self, db):
        r1 = make_correlation_rule(slug="r-a", name="Rule A")
        r2 = make_correlation_rule(slug="r-b", name="Rule B")
        db.add_all([r1, r2])
        db.flush()

        ws1 = make_watch_state(r1, user_id="carol@contoso.com", risk_contribution=10)
        ws2 = make_watch_state(r2, user_id="carol@contoso.com", risk_contribution=10)
        db.add_all([ws1, ws2])
        db.flush()

        scorer = RiskScorer(db)
        result = scorer.score_user("carol@contoso.com")

        assert result.active_windows == 2
        assert result.multiplier == 1.25
        expected = min(100, int((20 + 0) * 1.25))
        assert result.score == expected

    def test_multiplier_three_or_more_windows(self, db):
        rules = [make_correlation_rule(slug=f"r-{i}", name=f"Rule {i}") for i in range(3)]
        db.add_all(rules)
        db.flush()

        for rule in rules:
            db.add(make_watch_state(rule, user_id="dave@contoso.com", risk_contribution=15))
        db.flush()

        scorer = RiskScorer(db)
        result = scorer.score_user("dave@contoso.com")

        assert result.active_windows == 3
        assert result.multiplier == 1.5
        expected = min(100, int(45 * 1.5))
        assert result.score == expected

    def test_score_capped_at_100(self, db):
        rule = make_correlation_rule(slug="r-high", name="High Risk Rule")
        db.add(rule)
        db.flush()

        ws = make_watch_state(rule, user_id="eve@contoso.com", risk_contribution=100)
        db.add(ws)
        signin = make_signin_log(
            id="s-high",
            user_principal_name="eve@contoso.com",
            risk_level_during_sign_in="high",
        )
        db.add(signin)
        db.flush()

        scorer = RiskScorer(db)
        result = scorer.score_user("eve@contoso.com")
        assert result.score == 100

    def test_score_all_watched_users(self, db):
        r1 = make_correlation_rule(slug="all-1", name="All Rule 1")
        r2 = make_correlation_rule(slug="all-2", name="All Rule 2")
        db.add_all([r1, r2])
        db.flush()

        db.add(make_watch_state(r1, user_id="user1@test.com", risk_contribution=10))
        db.add(make_watch_state(r2, user_id="user2@test.com", risk_contribution=20))
        db.flush()

        scorer = RiskScorer(db)
        results = scorer.score_all_watched_users()
        assert len(results) == 2
        user_ids = {r.user_id for r in results}
        assert "user1@test.com" in user_ids
        assert "user2@test.com" in user_ids

    def test_get_high_risk_users_filters(self, db):
        r = make_correlation_rule(slug="hr-1", name="HR Rule")
        db.add(r)
        db.flush()

        db.add(make_watch_state(r, user_id="low@test.com", risk_contribution=5))
        db.add(make_watch_state(r, user_id="high@test.com", risk_contribution=60))
        db.flush()

        scorer = RiskScorer(db)
        results = scorer.get_high_risk_users(threshold=50)
        assert len(results) == 1
        assert results[0].user_id == "high@test.com"

    def test_expired_windows_ignored(self, db):
        rule = make_correlation_rule(slug="exp-1", name="Expired Rule")
        db.add(rule)
        db.flush()

        past = datetime.now(timezone.utc) - timedelta(days=30)
        ws = make_watch_state(
            rule,
            user_id="old@test.com",
            risk_contribution=50,
            window_start=past - timedelta(days=14),
            window_end=past,
            is_active=True,
        )
        db.add(ws)
        db.flush()

        scorer = RiskScorer(db)
        result = scorer.score_user("old@test.com")
        # Window is expired (window_end < now), should not contribute
        assert result.score == 0
        assert result.active_windows == 0
