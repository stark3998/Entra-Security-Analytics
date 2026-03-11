"""Compounding risk scorer.

Calculates a 0–100 risk score per user by combining:
  1. Active ``UserWatchState`` contributions.
  2. Built-in Entra ID risk level (from the latest sign-in).
  3. A multiplier when multiple watch windows overlap.

Scoring formula:
  base   = Σ (active watch-window risk_contribution)
  entra  = mapped Entra risk (none=0, low=5, medium=15, high=30)
  multi  = 1.0  (1 window)
           1.25 (2 windows)
           1.5  (3+ windows)
  score  = min(100, (base + entra) × multi)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, desc, select
from sqlalchemy.orm import Session

from app.models.database import SignInLog, UserWatchState

logger = logging.getLogger(__name__)

ENTRA_RISK_MAP: dict[str | None, int] = {
    None: 0,
    "none": 0,
    "hidden": 0,
    "low": 5,
    "medium": 15,
    "high": 30,
}

MULTIPLIER_THRESHOLDS: list[tuple[int, float]] = [
    (3, 1.5),
    (2, 1.25),
]


class RiskScorer:
    """Calculate composite risk scores for users."""

    def __init__(self, db: Session) -> None:
        self._db = db

    def score_user(self, user_id: str) -> RiskResult:
        """Compute the current risk score for a single user."""
        now = datetime.now(timezone.utc)

        # 1. Active watch windows
        windows = list(
            self._db.execute(
                select(UserWatchState).where(
                    and_(
                        UserWatchState.user_id == user_id,
                        UserWatchState.is_active == True,  # noqa: E712
                        UserWatchState.window_end > now,
                    )
                )
            ).scalars().all()
        )
        base_risk = sum(ws.risk_contribution for ws in windows)
        window_count = len(windows)

        # 2. Entra ID built-in risk from latest sign-in
        latest_signin = self._db.execute(
            select(SignInLog)
            .where(SignInLog.user_principal_name == user_id)
            .order_by(desc(SignInLog.created_date_time))
            .limit(1)
        ).scalars().first()

        entra_risk = 0
        entra_level = None
        if latest_signin:
            entra_level = latest_signin.risk_level_during_sign_in
            entra_risk = ENTRA_RISK_MAP.get(entra_level, 0)

        # 3. Multiplier
        multiplier = 1.0
        for threshold, mult in MULTIPLIER_THRESHOLDS:
            if window_count >= threshold:
                multiplier = mult
                break

        raw_score = (base_risk + entra_risk) * multiplier
        final_score = min(100, int(raw_score))

        return RiskResult(
            user_id=user_id,
            score=final_score,
            base_risk=base_risk,
            entra_risk=entra_risk,
            entra_risk_level=entra_level,
            multiplier=multiplier,
            active_windows=window_count,
            window_details=[
                {
                    "rule_id": ws.rule_id,
                    "rule_name": ws.rule.name if ws.rule else None,
                    "rule_slug": ws.rule.slug if ws.rule else None,
                    "rule_description": ws.rule.description if ws.rule else None,
                    "risk_contribution": ws.risk_contribution,
                    "window_start": ws.window_start.isoformat() if ws.window_start else None,
                    "window_end": ws.window_end.isoformat(),
                    "trigger_event_id": ws.trigger_event_id,
                    "trigger_event_source": ws.trigger_event_source,
                }
                for ws in windows
            ],
        )

    def score_all_watched_users(self) -> list[RiskResult]:
        """Score every user with at least one active watch window."""
        now = datetime.now(timezone.utc)
        user_ids = list(
            self._db.execute(
                select(UserWatchState.user_id)
                .where(
                    and_(
                        UserWatchState.is_active == True,  # noqa: E712
                        UserWatchState.window_end > now,
                    )
                )
                .distinct()
            ).scalars().all()
        )
        return [self.score_user(uid) for uid in user_ids]

    def get_high_risk_users(self, threshold: int = 50) -> list[RiskResult]:
        """Return users whose score meets or exceeds the threshold."""
        all_scores = self.score_all_watched_users()
        return [r for r in all_scores if r.score >= threshold]


class RiskResult:
    """Value object holding a user's risk breakdown."""

    __slots__ = (
        "user_id",
        "score",
        "base_risk",
        "entra_risk",
        "entra_risk_level",
        "multiplier",
        "active_windows",
        "window_details",
    )

    def __init__(
        self,
        user_id: str,
        score: int,
        base_risk: int,
        entra_risk: int,
        entra_risk_level: str | None,
        multiplier: float,
        active_windows: int,
        window_details: list[dict[str, Any]],
    ) -> None:
        self.user_id = user_id
        self.score = score
        self.base_risk = base_risk
        self.entra_risk = entra_risk
        self.entra_risk_level = entra_risk_level
        self.multiplier = multiplier
        self.active_windows = active_windows
        self.window_details = window_details

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_id": self.user_id,
            "score": self.score,
            "base_risk": self.base_risk,
            "entra_risk": self.entra_risk,
            "entra_risk_level": self.entra_risk_level,
            "multiplier": self.multiplier,
            "active_windows": self.active_windows,
            "window_details": self.window_details,
        }

    def __repr__(self) -> str:
        return f"RiskResult(user={self.user_id!r}, score={self.score})"
