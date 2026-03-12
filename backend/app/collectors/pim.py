"""Collector for PIM (Privileged Identity Management) data from Microsoft Graph.

Fetches role definitions, active assignments, eligible assignments, and
activation requests. This is a snapshot sync — it replaces all cached rows
each run, similar to the CA policy collector.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from app.models.database import (
    PIMActivationRequest,
    PIMRoleAssignment,
    PIMRoleDefinition,
    PIMRoleEligibility,
)

logger = logging.getLogger(__name__)

# Microsoft Graph endpoints
# Using read-only compatible endpoints (Directory.Read.All / RoleManagement.Read.Directory)
ROLE_DEFINITIONS_URL = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions"
# unifiedRoleAssignment — works with Directory.Read.All (no write perms needed)
ROLE_ASSIGNMENTS_URL = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
# roleEligibilitySchedules — read-only compatible via beta
ROLE_ELIGIBILITIES_URL = "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilityScheduleInstances"
# roleAssignmentScheduleRequests — try beta with $filter for recent requests
ROLE_REQUESTS_URL = "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentScheduleRequests"

# Retry configuration
MAX_RETRIES = 5
INITIAL_BACKOFF = 1.0
BACKOFF_MULTIPLIER = 2.0
RATE_LIMIT_STATUS = 429
SERVER_ERROR_THRESHOLD = 500


class PIMCollectorError(Exception):
    """Raised when the PIM collector hits an unrecoverable error."""


class PIMCollector:
    """Fetches PIM role definitions, assignments, eligibilities, and activation requests.

    Performs a full-snapshot sync (like CAPolicyCollector).
    """

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
            current_params = None
        return all_items

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
                    logger.warning("PIM: Rate limited (429). Waiting %.1fs (attempt %d/%d)", wait, attempt, MAX_RETRIES)
                    await asyncio.sleep(wait)
                elif status >= SERVER_ERROR_THRESHOLD:
                    logger.warning("PIM: Server error %d. Retrying in %.1fs (attempt %d/%d)", status, backoff, attempt, MAX_RETRIES)
                    await asyncio.sleep(backoff)
                    backoff *= BACKOFF_MULTIPLIER
                else:
                    raise PIMCollectorError(f"HTTP {status}: {exc.response.text}") from exc
            except (httpx.ConnectError, httpx.ReadTimeout) as exc:
                logger.warning("PIM: Network error: %s. Retrying in %.1fs (attempt %d/%d)", exc, backoff, attempt, MAX_RETRIES)
                await asyncio.sleep(backoff)
                backoff *= BACKOFF_MULTIPLIER

        raise PIMCollectorError(f"Max retries ({MAX_RETRIES}) exceeded for {url}")

    # ── Fetch helpers ─────────────────────────────────────────

    async def fetch_role_definitions(self, token: str) -> list[dict[str, Any]]:
        return await self._get_all_pages(ROLE_DEFINITIONS_URL, token)

    async def fetch_assignments(self, token: str) -> list[dict[str, Any]]:
        # $expand=principal gets display name + type inline
        return await self._get_all_pages(
            ROLE_ASSIGNMENTS_URL, token,
            params={"$expand": "principal"},
        )

    async def fetch_eligibilities(self, token: str) -> list[dict[str, Any]]:
        """Fetch eligible assignments. Uses beta endpoint — may fail if PIM is not licensed."""
        try:
            return await self._get_all_pages(ROLE_ELIGIBILITIES_URL, token)
        except PIMCollectorError as exc:
            logger.warning("PIM eligibilities fetch failed (may require P2 license): %s", exc)
            return []

    async def fetch_activation_requests(self, token: str) -> list[dict[str, Any]]:
        """Fetch activation requests. Uses beta endpoint — may fail without PIM license."""
        try:
            return await self._get_all_pages(
                ROLE_REQUESTS_URL, token,
                params={"$orderby": "createdDateTime desc", "$top": "500"},
            )
        except PIMCollectorError as exc:
            logger.warning("PIM activation requests fetch failed (may require P2 license): %s", exc)
            return []

    # ── Normalisation ─────────────────────────────────────────

    @staticmethod
    def _parse_dt(value: str | None) -> datetime | None:
        if not value:
            return None
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def normalize_role_definitions(self, raw: list[dict[str, Any]]) -> list[PIMRoleDefinition]:
        now = datetime.now(timezone.utc)
        return [
            PIMRoleDefinition(
                id=r["id"],
                display_name=r.get("displayName", ""),
                description=r.get("description", ""),
                is_built_in=r.get("isBuiltIn", True),
                is_enabled=r.get("isEnabled", True),
                raw_json=r,
                synced_at=now,
            )
            for r in raw
        ]

    def normalize_assignments(
        self, raw: list[dict[str, Any]], role_map: dict[str, str]
    ) -> list[PIMRoleAssignment]:
        """Normalize unifiedRoleAssignment objects (from /roleAssignments?$expand=principal)."""
        now = datetime.now(timezone.utc)
        results: list[PIMRoleAssignment] = []
        for r in raw:
            role_def_id = r.get("roleDefinitionId", "")
            principal = r.get("principal", {}) or {}
            # unifiedRoleAssignment doesn't have schedule fields — these are
            # permanent/standing assignments. assignmentType and memberType
            # may be present if the API version supports them.
            results.append(
                PIMRoleAssignment(
                    id=r.get("id", ""),
                    principal_id=r.get("principalId", ""),
                    principal_display_name=principal.get("displayName", ""),
                    principal_type=principal.get("@odata.type", "").replace("#microsoft.graph.", ""),
                    role_definition_id=role_def_id,
                    role_display_name=role_map.get(role_def_id, ""),
                    directory_scope_id=r.get("directoryScopeId", "/"),
                    assignment_type=r.get("assignmentType", "Assigned"),
                    member_type=r.get("memberType", "Direct"),
                    start_date_time=self._parse_dt(r.get("startDateTime")),
                    end_date_time=self._parse_dt(r.get("endDateTime")),
                    raw_json=r,
                    synced_at=now,
                )
            )
        return results

    def normalize_eligibilities(
        self, raw: list[dict[str, Any]], role_map: dict[str, str]
    ) -> list[PIMRoleEligibility]:
        now = datetime.now(timezone.utc)
        results: list[PIMRoleEligibility] = []
        for r in raw:
            role_def_id = r.get("roleDefinitionId", "")
            principal = r.get("principal", {}) or {}
            results.append(
                PIMRoleEligibility(
                    id=r.get("id", ""),
                    principal_id=r.get("principalId", ""),
                    principal_display_name=principal.get("displayName", ""),
                    principal_type=principal.get("@odata.type", "").replace("#microsoft.graph.", ""),
                    role_definition_id=role_def_id,
                    role_display_name=role_map.get(role_def_id, ""),
                    directory_scope_id=r.get("directoryScopeId", "/"),
                    member_type=r.get("memberType", ""),
                    start_date_time=self._parse_dt(r.get("startDateTime")),
                    end_date_time=self._parse_dt(r.get("endDateTime")),
                    raw_json=r,
                    synced_at=now,
                )
            )
        return results

    def normalize_activation_requests(
        self, raw: list[dict[str, Any]], role_map: dict[str, str]
    ) -> list[PIMActivationRequest]:
        now = datetime.now(timezone.utc)
        results: list[PIMActivationRequest] = []
        for r in raw:
            role_def_id = r.get("roleDefinitionId", "")
            # Extract schedule info
            schedule = r.get("scheduleInfo", {}) or {}
            start_dt = schedule.get("startDateTime")
            expiration = schedule.get("expiration", {}) or {}
            end_dt = expiration.get("endDateTime")

            results.append(
                PIMActivationRequest(
                    id=r.get("id", ""),
                    principal_id=r.get("principalId", ""),
                    principal_display_name=r.get("principal", {}).get("displayName", "") if r.get("principal") else "",
                    role_definition_id=role_def_id,
                    role_display_name=role_map.get(role_def_id, ""),
                    action=r.get("action", ""),
                    status=r.get("status", ""),
                    justification=r.get("justification", "") or "",
                    created_date_time=self._parse_dt(r.get("createdDateTime")),
                    schedule_start=self._parse_dt(start_dt),
                    schedule_end=self._parse_dt(end_dt),
                    raw_json=r,
                    synced_at=now,
                )
            )
        return results

    # ── Full sync orchestrator ────────────────────────────────

    async def sync_all(self, token: str, db: Any) -> dict[str, int]:
        """Perform a full snapshot sync of all PIM data."""
        # Fetch concurrently
        raw_defs, raw_assigns, raw_eligs, raw_reqs = await asyncio.gather(
            self.fetch_role_definitions(token),
            self.fetch_assignments(token),
            self.fetch_eligibilities(token),
            self.fetch_activation_requests(token),
        )

        # Build role name lookup
        role_map = {r["id"]: r.get("displayName", "") for r in raw_defs}

        # Normalise
        definitions = self.normalize_role_definitions(raw_defs)
        assignments = self.normalize_assignments(raw_assigns, role_map)
        eligibilities = self.normalize_eligibilities(raw_eligs, role_map)
        requests = self.normalize_activation_requests(raw_reqs, role_map)

        # Full replace
        db.query(PIMActivationRequest).delete()
        db.query(PIMRoleAssignment).delete()
        db.query(PIMRoleEligibility).delete()
        db.query(PIMRoleDefinition).delete()
        db.flush()

        db.add_all(definitions)
        db.add_all(assignments)
        db.add_all(eligibilities)
        db.add_all(requests)
        db.commit()

        counts = {
            "role_definitions": len(definitions),
            "assignments": len(assignments),
            "eligibilities": len(eligibilities),
            "activation_requests": len(requests),
        }
        logger.info("PIM sync complete: %s", counts)
        return counts


def _retry_after(response: httpx.Response) -> float:
    try:
        return float(response.headers.get("Retry-After", "30"))
    except (ValueError, TypeError):
        return 30.0
