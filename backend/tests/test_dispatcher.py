"""Tests for the alert dispatcher."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.alerting.dispatcher import AlertDispatcher
from app.models.database import (
    AlertDeliveryStatus,
    AlertHistoryEntry,
    Incident,
    IncidentStatus,
    Severity,
)

from tests.conftest import make_correlation_rule, make_incident


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture()
def _seed_rule(db):
    """Insert a rule so incidents can reference it."""
    rule = make_correlation_rule(slug="disp-rule", name="Dispatch Rule")
    db.add(rule)
    db.flush()
    return rule


@pytest.fixture()
def dispatcher(db, settings):
    with patch("app.config._settings", settings):
        d = AlertDispatcher(db, min_severity=Severity.MEDIUM)
    return d


# ── Tests ─────────────────────────────────────────────────────────────────


class TestAlertDispatcher:
    """Tests for AlertDispatcher."""

    @pytest.mark.asyncio
    async def test_dispatch_empty_list(self, dispatcher):
        sent = await dispatcher.dispatch([])
        assert sent == 0

    @pytest.mark.asyncio
    async def test_below_threshold_skipped(self, db, dispatcher, _seed_rule):
        """LOW severity should be skipped when threshold is MEDIUM."""
        inc = make_incident(_seed_rule, severity=Severity.LOW)
        db.add(inc)
        db.flush()

        sent = await dispatcher.dispatch([inc])
        assert sent == 0

    @pytest.mark.asyncio
    async def test_meets_threshold_dispatches(self, db, settings, _seed_rule):
        """HIGH severity should be dispatched."""
        inc = make_incident(_seed_rule, severity=Severity.HIGH)
        db.add(inc)
        db.flush()

        mock_email = AsyncMock(return_value=True)
        mock_teams = AsyncMock(return_value=True)
        mock_slack = AsyncMock(return_value=True)

        with patch("app.config._settings", settings):
            dispatcher = AlertDispatcher(db, min_severity=Severity.MEDIUM)

        # Replace channel send methods
        for ch in dispatcher._channels:
            ch.send = mock_email  # simplify: all channels mock

        sent = await dispatcher.dispatch([inc])
        assert sent == 3  # 3 channels

    @pytest.mark.asyncio
    async def test_failed_delivery_recorded(self, db, settings, _seed_rule):
        """A failing alerter should still record the failure."""
        inc = make_incident(_seed_rule, severity=Severity.CRITICAL)
        db.add(inc)
        db.flush()

        with patch("app.config._settings", settings):
            dispatcher = AlertDispatcher(db, min_severity=Severity.LOW)

        # Make all channels fail
        for ch in dispatcher._channels:
            ch.send = AsyncMock(return_value=False)

        sent = await dispatcher.dispatch([inc])
        db.flush()

        assert sent == 0
        history = db.query(AlertHistoryEntry).filter_by(incident_id=inc.id).all()
        assert len(history) == 3
        assert all(h.status == AlertDeliveryStatus.FAILED for h in history)

    @pytest.mark.asyncio
    async def test_exception_in_channel_handled(self, db, settings, _seed_rule):
        """Exceptions in alerter.send should be caught and recorded."""
        inc = make_incident(_seed_rule, severity=Severity.HIGH)
        db.add(inc)
        db.flush()

        with patch("app.config._settings", settings):
            dispatcher = AlertDispatcher(db, min_severity=Severity.MEDIUM)

        # Make one channel raise
        for ch in dispatcher._channels:
            ch.send = AsyncMock(side_effect=RuntimeError("network error"))

        sent = await dispatcher.dispatch([inc])
        db.flush()

        assert sent == 0
        history = db.query(AlertHistoryEntry).filter_by(incident_id=inc.id).all()
        assert len(history) == 3
        assert all(h.status == AlertDeliveryStatus.FAILED for h in history)

    @pytest.mark.asyncio
    async def test_severity_ordering(self, db, settings, _seed_rule):
        """Verify severity ordering: INFO < LOW < MEDIUM < HIGH < CRITICAL."""
        from app.alerting.dispatcher import _SEVERITY_ORDER

        assert _SEVERITY_ORDER[Severity.INFO] < _SEVERITY_ORDER[Severity.LOW]
        assert _SEVERITY_ORDER[Severity.LOW] < _SEVERITY_ORDER[Severity.MEDIUM]
        assert _SEVERITY_ORDER[Severity.MEDIUM] < _SEVERITY_ORDER[Severity.HIGH]
        assert _SEVERITY_ORDER[Severity.HIGH] < _SEVERITY_ORDER[Severity.CRITICAL]

    @pytest.mark.asyncio
    async def test_multiple_incidents_dispatched(self, db, settings, _seed_rule):
        """Multiple qualifying incidents should each be dispatched."""
        inc1 = make_incident(_seed_rule, title="Inc 1", severity=Severity.HIGH)
        inc2 = make_incident(_seed_rule, title="Inc 2", severity=Severity.CRITICAL)
        db.add_all([inc1, inc2])
        db.flush()

        with patch("app.config._settings", settings):
            dispatcher = AlertDispatcher(db, min_severity=Severity.MEDIUM)

        for ch in dispatcher._channels:
            ch.send = AsyncMock(return_value=True)

        sent = await dispatcher.dispatch([inc1, inc2])
        assert sent == 6  # 2 incidents × 3 channels
