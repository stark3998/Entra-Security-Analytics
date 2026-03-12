"""Collector for Entra ID user profiles from Microsoft Graph.

Fetches all users with key profile fields and stores them in the
``entra_users`` table.  This is a snapshot sync — it replaces all cached
rows each run, similar to the PIM and CA policy collectors.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from app.models.database import EntraUser

logger = logging.getLogger(__name__)

USERS_URL = "https://graph.microsoft.com/v1.0/users"
USER_SELECT = (
    "id,displayName,userPrincipalName,mail,jobTitle,department,"
    "officeLocation,mobilePhone,companyName,accountEnabled,userType,"
    "createdDateTime,assignedLicenses,assignedPlans,signInActivity"
)

# Retry configuration (matches PIM collector)
MAX_RETRIES = 5
INITIAL_BACKOFF = 1.0
BACKOFF_MULTIPLIER = 2.0
RATE_LIMIT_STATUS = 429
SERVER_ERROR_THRESHOLD = 500


class UserCollectorError(Exception):
    """Raised when the user collector hits an unrecoverable error."""


class UserCollector:
    """Fetches Entra ID user profiles from Microsoft Graph."""

    def __init__(self, http_client: httpx.AsyncClient | None = None) -> None:
        self._client = http_client or httpx.AsyncClient(timeout=30.0)
        self._owns_client = http_client is None

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # ── HTTP helpers ──────────────────────────────────────────

    async def _get(
        self, url: str, token: str, params: dict[str, str] | None = None
    ) -> httpx.Response:
        resp = await self._client.get(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            params=params,
        )
        resp.raise_for_status()
        return resp

    async def _get_with_retry(
        self, url: str, token: str, params: dict[str, str] | None = None
    ) -> dict[str, Any]:
        backoff = INITIAL_BACKOFF
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = await self._get(url, token, params)
                return resp.json()
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if status == RATE_LIMIT_STATUS:
                    wait = _retry_after(exc.response)
                    logger.warning(
                        "Users: Rate limited (429). Waiting %.1fs (attempt %d/%d)",
                        wait, attempt, MAX_RETRIES,
                    )
                    await asyncio.sleep(wait)
                elif status >= SERVER_ERROR_THRESHOLD:
                    logger.warning(
                        "Users: Server error %d. Retrying in %.1fs (attempt %d/%d)",
                        status, backoff, attempt, MAX_RETRIES,
                    )
                    await asyncio.sleep(backoff)
                    backoff *= BACKOFF_MULTIPLIER
                else:
                    raise UserCollectorError(
                        f"HTTP {status}: {exc.response.text}"
                    ) from exc
            except (httpx.ConnectError, httpx.ReadTimeout) as exc:
                logger.warning(
                    "Users: Network error: %s. Retrying in %.1fs (attempt %d/%d)",
                    exc, backoff, attempt, MAX_RETRIES,
                )
                await asyncio.sleep(backoff)
                backoff *= BACKOFF_MULTIPLIER

        raise UserCollectorError(f"Max retries ({MAX_RETRIES}) exceeded for {url}")

    async def _get_all_pages(
        self, url: str, token: str, params: dict[str, str] | None = None
    ) -> list[dict[str, Any]]:
        all_items: list[dict[str, Any]] = []
        next_link: str | None = url
        current_params = params

        while next_link:
            data = await self._get_with_retry(next_link, token, current_params)
            all_items.extend(data.get("value", []))
            next_link = data.get("@odata.nextLink")
            current_params = None  # nextLink includes params
        return all_items

    # ── Fetch ─────────────────────────────────────────────────

    async def fetch_users(self, token: str) -> list[dict[str, Any]]:
        """Fetch all users from Graph API."""
        try:
            return await self._get_all_pages(
                USERS_URL, token,
                params={"$select": USER_SELECT, "$top": "999"},
            )
        except UserCollectorError:
            # signInActivity requires AuditLog.Read.All — retry without it
            logger.warning(
                "Users: fetch with signInActivity failed, retrying without it"
            )
            fallback_select = USER_SELECT.replace(",signInActivity", "")
            return await self._get_all_pages(
                USERS_URL, token,
                params={"$select": fallback_select, "$top": "999"},
            )

    async def fetch_user_by_id(
        self, token: str, user_id: str
    ) -> dict[str, Any] | None:
        """Fetch a single user by object ID. Returns None on 404."""
        try:
            data = await self._get_with_retry(
                f"{USERS_URL}/{user_id}", token,
                params={"$select": USER_SELECT},
            )
            return data
        except UserCollectorError as exc:
            if "404" in str(exc):
                return None
            raise

    # ── Normalisation ─────────────────────────────────────────

    @staticmethod
    def _parse_dt(value: str | None) -> datetime | None:
        if not value:
            return None
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def normalize_users(self, raw: list[dict[str, Any]]) -> list[EntraUser]:
        now = datetime.now(timezone.utc)
        results: list[EntraUser] = []
        for r in raw:
            sign_in_activity = r.get("signInActivity", {}) or {}
            last_sign_in = sign_in_activity.get("lastSignInDateTime")

            results.append(
                EntraUser(
                    id=r.get("id", ""),
                    user_principal_name=r.get("userPrincipalName", ""),
                    display_name=r.get("displayName", ""),
                    mail=r.get("mail", "") or "",
                    job_title=r.get("jobTitle", "") or "",
                    department=r.get("department", "") or "",
                    office_location=r.get("officeLocation", "") or "",
                    mobile_phone=r.get("mobilePhone", "") or "",
                    company_name=r.get("companyName", "") or "",
                    account_enabled=r.get("accountEnabled", True),
                    user_type=r.get("userType", "") or "",
                    created_date_time=self._parse_dt(r.get("createdDateTime")),
                    last_sign_in_date_time=self._parse_dt(last_sign_in),
                    assigned_licenses=r.get("assignedLicenses", []) or [],
                    assigned_plans=r.get("assignedPlans", []) or [],
                    raw_json=r,
                    synced_at=now,
                )
            )
        return results

    # ── Full sync orchestrator ────────────────────────────────

    async def sync_all(self, token: str, db: Any) -> dict[str, int]:
        """Perform a full snapshot sync of all Entra users."""
        raw_users = await self.fetch_users(token)
        users = self.normalize_users(raw_users)

        # Full replace
        db.query(EntraUser).delete()
        db.flush()
        db.add_all(users)
        db.commit()

        count = len(users)
        logger.info("User directory sync complete: %d users", count)
        return {"users": count}


def _retry_after(response: httpx.Response) -> float:
    try:
        return float(response.headers.get("Retry-After", "30"))
    except (ValueError, TypeError):
        return 30.0
