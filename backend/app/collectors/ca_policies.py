"""Collector for Conditional Access policies, named locations,
authentication strengths, and directory groups/roles from Microsoft Graph.

This is a *snapshot* sync – it replaces all cached rows each run rather than
appending time-range pages like the log collectors.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from app.models.database import (
    AuthenticationStrength,
    ConditionalAccessPolicy,
    DirectoryGroup,
    NamedLocation,
    PolicyCoverageCache,
)

logger = logging.getLogger(__name__)

# Microsoft Graph v1.0 endpoints
POLICIES_URL = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
NAMED_LOCATIONS_URL = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"
AUTH_STRENGTHS_URL = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationStrength/policies"
GROUPS_URL = "https://graph.microsoft.com/v1.0/groups"
DIRECTORY_ROLES_URL = "https://graph.microsoft.com/v1.0/directoryRoles"

# Retry configuration (mirrors base collector)
MAX_RETRIES = 5
INITIAL_BACKOFF = 1.0
BACKOFF_MULTIPLIER = 2.0
RATE_LIMIT_STATUS = 429
SERVER_ERROR_THRESHOLD = 500

# Well-known CA target constants (ALL users / ALL apps)
ALL_USERS = "All"
ALL_APPLICATIONS = "All"
NONE = "None"


class CAPolicyCollectorError(Exception):
    """Raised when the CA policy collector hits an unrecoverable error."""


class CAPolicyCollector:
    """Fetches CA policies, named locations, auth strengths, and groups/roles.

    Unlike log collectors this does NOT extend BaseCollector because it
    performs a full-snapshot sync rather than time-range pagination.
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
        """Authenticated GET with raise_for_status."""
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
        """Follow @odata.nextLink until all pages are collected, with retry."""
        all_items: list[dict[str, Any]] = []
        next_link: str | None = url
        current_params = params

        while next_link:
            data = await self._get_with_retry(next_link, token, current_params)
            all_items.extend(data.get("value", []))
            next_link = data.get("@odata.nextLink")
            current_params = None  # nextLink includes query params
        return all_items

    async def _get_with_retry(
        self, url: str, token: str, params: dict[str, str] | None = None
    ) -> dict[str, Any]:
        """Single-page GET with exponential-backoff retry on 429 / 5xx."""
        backoff = INITIAL_BACKOFF
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = await self._get(url, token, params)
                return resp.json()
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if status == RATE_LIMIT_STATUS:
                    wait = _retry_after(exc.response)
                    logger.warning("Rate limited (429). Waiting %.1fs (attempt %d/%d)", wait, attempt, MAX_RETRIES)
                    await asyncio.sleep(wait)
                elif status >= SERVER_ERROR_THRESHOLD:
                    logger.warning("Server error %d. Retrying in %.1fs (attempt %d/%d)", status, backoff, attempt, MAX_RETRIES)
                    await asyncio.sleep(backoff)
                    backoff *= BACKOFF_MULTIPLIER
                else:
                    raise CAPolicyCollectorError(
                        f"HTTP {status}: {exc.response.text}"
                    ) from exc
            except (httpx.ConnectError, httpx.ReadTimeout) as exc:
                logger.warning("Network error: %s. Retrying in %.1fs (attempt %d/%d)", exc, backoff, attempt, MAX_RETRIES)
                await asyncio.sleep(backoff)
                backoff *= BACKOFF_MULTIPLIER

        raise CAPolicyCollectorError(f"Max retries ({MAX_RETRIES}) exceeded for {url}")

    # ── Fetch helpers ─────────────────────────────────────────

    async def fetch_policies(self, token: str) -> list[dict[str, Any]]:
        """Fetch all conditional access policies."""
        return await self._get_all_pages(POLICIES_URL, token)

    async def fetch_named_locations(self, token: str) -> list[dict[str, Any]]:
        """Fetch all named / trusted locations."""
        return await self._get_all_pages(NAMED_LOCATIONS_URL, token)

    async def fetch_auth_strengths(self, token: str) -> list[dict[str, Any]]:
        """Fetch all authentication strength policies."""
        return await self._get_all_pages(AUTH_STRENGTHS_URL, token)

    async def fetch_directory_roles(self, token: str) -> list[dict[str, Any]]:
        """Fetch activated directory roles."""
        return await self._get_all_pages(DIRECTORY_ROLES_URL, token)

    async def fetch_group(self, token: str, group_id: str) -> dict[str, Any] | None:
        """Fetch a single group by ID (returns None on 404)."""
        try:
            resp = await self._get(f"{GROUPS_URL}/{group_id}", token)
            return resp.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                logger.debug("Group %s not found", group_id)
                return None
            raise

    # ── Normalisation ─────────────────────────────────────────

    @staticmethod
    def _parse_dt(value: str | None) -> datetime | None:
        if not value:
            return None
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def normalize_policies(self, raw: list[dict[str, Any]]) -> list[ConditionalAccessPolicy]:
        now = datetime.now(timezone.utc)
        return [
            ConditionalAccessPolicy(
                id=p["id"],
                display_name=p.get("displayName", ""),
                state=p.get("state", "disabled"),
                created_date_time=self._parse_dt(p.get("createdDateTime")),
                modified_date_time=self._parse_dt(p.get("modifiedDateTime")),
                conditions=p.get("conditions", {}),
                grant_controls=p.get("grantControls", {}),
                session_controls=p.get("sessionControls", {}),
                raw_json=p,
                synced_at=now,
            )
            for p in raw
        ]

    def normalize_locations(self, raw: list[dict[str, Any]]) -> list[NamedLocation]:
        now = datetime.now(timezone.utc)
        results: list[NamedLocation] = []
        for loc in raw:
            odata_type = loc.get("@odata.type", "")
            if "ipNamedLocation" in odata_type:
                loc_type = "ipRange"
            elif "countryNamedLocation" in odata_type:
                loc_type = "countryNamedLocation"
            else:
                loc_type = "unknown"

            results.append(
                NamedLocation(
                    id=loc["id"],
                    display_name=loc.get("displayName", ""),
                    is_trusted=loc.get("isTrusted", False),
                    location_type=loc_type,
                    ip_ranges=[r.get("cidrAddress", str(r)) for r in loc.get("ipRanges", [])],
                    countries_and_regions=loc.get("countriesAndRegions", []),
                    include_unknown_countries=loc.get("includeUnknownCountriesAndRegions", False),
                    raw_json=loc,
                    synced_at=now,
                )
            )
        return results

    def normalize_auth_strengths(self, raw: list[dict[str, Any]]) -> list[AuthenticationStrength]:
        now = datetime.now(timezone.utc)
        return [
            AuthenticationStrength(
                id=a["id"],
                display_name=a.get("displayName", ""),
                description=a.get("description", ""),
                policy_type=a.get("policyType", ""),
                requirements_satisfied=a.get("requirementsSatisfied", ""),
                allowed_combinations=a.get("allowedCombinations", []),
                raw_json=a,
                synced_at=now,
            )
            for a in raw
        ]

    def normalize_groups(self, raw: list[dict[str, Any]], object_type: str = "group") -> list[DirectoryGroup]:
        now = datetime.now(timezone.utc)
        return [
            DirectoryGroup(
                id=g["id"],
                display_name=g.get("displayName", ""),
                object_type=object_type,
                description=g.get("description", "") or "",
                synced_at=now,
            )
            for g in raw
        ]

    # ── Coverage-map builder ──────────────────────────────────

    def build_coverage_entries(
        self, policies: list[ConditionalAccessPolicy]
    ) -> list[PolicyCoverageCache]:
        """Denormalize policy conditions into flat coverage rows."""
        now = datetime.now(timezone.utc)
        entries: list[PolicyCoverageCache] = []

        for pol in policies:
            conditions = pol.conditions or {}

            # Users
            users = conditions.get("users", {}) or {}
            entries.extend(self._coverage_from_list(pol.id, "user", users.get("includeUsers", []), "include", now))
            entries.extend(self._coverage_from_list(pol.id, "user", users.get("excludeUsers", []), "exclude", now))
            entries.extend(self._coverage_from_list(pol.id, "group", users.get("includeGroups", []), "include", now))
            entries.extend(self._coverage_from_list(pol.id, "group", users.get("excludeGroups", []), "exclude", now))
            entries.extend(self._coverage_from_list(pol.id, "role", users.get("includeRoles", []), "include", now))
            entries.extend(self._coverage_from_list(pol.id, "role", users.get("excludeRoles", []), "exclude", now))

            # Applications
            apps = conditions.get("applications", {}) or {}
            entries.extend(self._coverage_from_list(pol.id, "application", apps.get("includeApplications", []), "include", now))
            entries.extend(self._coverage_from_list(pol.id, "application", apps.get("excludeApplications", []), "exclude", now))

            # Platforms
            platforms = conditions.get("platforms", {}) or {}
            entries.extend(self._coverage_from_list(pol.id, "platform", platforms.get("includePlatforms", []), "include", now))
            entries.extend(self._coverage_from_list(pol.id, "platform", platforms.get("excludePlatforms", []), "exclude", now))

            # Locations
            locations = conditions.get("locations", {}) or {}
            entries.extend(self._coverage_from_list(pol.id, "location", locations.get("includeLocations", []), "include", now))
            entries.extend(self._coverage_from_list(pol.id, "location", locations.get("excludeLocations", []), "exclude", now))

        return entries

    @staticmethod
    def _coverage_from_list(
        policy_id: str,
        entity_type: str,
        ids: list[str] | None,
        inclusion_type: str,
        now: datetime,
    ) -> list[PolicyCoverageCache]:
        if not ids:
            return []
        return [
            PolicyCoverageCache(
                policy_id=policy_id,
                entity_type=entity_type,
                entity_id=eid,
                entity_display_name="",  # resolved later via DirectoryGroup lookup
                inclusion_type=inclusion_type,
                synced_at=now,
            )
            for eid in ids
        ]

    # ── Search / resolve helpers for live lookup ────────────────

    async def search_user(self, token: str, query: str) -> dict[str, Any] | None:
        """Search for a user by ID, UPN, or displayName."""
        # Try direct lookup first (works for ID and UPN)
        try:
            resp = await self._get(
                f"https://graph.microsoft.com/v1.0/users/{query}",
                token,
                params={"$select": "id,displayName,userPrincipalName"},
            )
            return resp.json()
        except Exception:
            pass
        # Fall back to search by displayName
        try:
            data = await self._get_with_retry(
                "https://graph.microsoft.com/v1.0/users",
                token,
                params={
                    "$filter": f"startswith(displayName,'{query}') or startswith(userPrincipalName,'{query}')",
                    "$select": "id,displayName,userPrincipalName",
                    "$top": "5",
                },
            )
            items = data.get("value", [])
            return items[0] if items else None
        except Exception:
            return None

    async def search_group(self, token: str, query: str) -> dict[str, Any] | None:
        """Search for a group by ID or displayName."""
        try:
            resp = await self._get(
                f"{GROUPS_URL}/{query}",
                token,
                params={"$select": "id,displayName"},
            )
            return resp.json()
        except Exception:
            pass
        try:
            data = await self._get_with_retry(
                GROUPS_URL,
                token,
                params={
                    "$filter": f"startswith(displayName,'{query}')",
                    "$select": "id,displayName",
                    "$top": "5",
                },
            )
            items = data.get("value", [])
            return items[0] if items else None
        except Exception:
            return None

    async def search_application(self, token: str, query: str) -> dict[str, Any] | None:
        """Search for a service principal / application by ID, appId, or displayName."""
        sp_url = "https://graph.microsoft.com/v1.0/servicePrincipals"
        # Try by appId
        try:
            data = await self._get_with_retry(
                sp_url,
                token,
                params={
                    "$filter": f"appId eq '{query}'",
                    "$select": "id,appId,displayName",
                    "$top": "1",
                },
            )
            items = data.get("value", [])
            if items:
                return items[0]
        except Exception:
            pass
        # Try by displayName
        try:
            data = await self._get_with_retry(
                sp_url,
                token,
                params={
                    "$filter": f"startswith(displayName,'{query}')",
                    "$select": "id,appId,displayName",
                    "$top": "5",
                },
            )
            items = data.get("value", [])
            return items[0] if items else None
        except Exception:
            return None

    async def get_user_group_ids(self, token: str, user_id: str) -> list[str]:
        """Get group and directory role IDs a user is a member of."""
        try:
            data = await self._get_all_pages(
                f"https://graph.microsoft.com/v1.0/users/{user_id}/memberOf",
                token,
                params={"$select": "id"},
            )
            return [m["id"] for m in data if "id" in m]
        except Exception:
            return []

    # ── Full sync orchestrator ────────────────────────────────

    async def sync_all(self, token: str, db: Any) -> dict[str, int]:
        """Perform a full snapshot sync of all CA-related data.

        Returns a dict of entity counts synced.
        """
        # Fetch all data concurrently
        raw_policies, raw_locations, raw_strengths, raw_roles = await asyncio.gather(
            self.fetch_policies(token),
            self.fetch_named_locations(token),
            self.fetch_auth_strengths(token),
            self.fetch_directory_roles(token),
        )

        # Normalise
        policies = self.normalize_policies(raw_policies)
        locations = self.normalize_locations(raw_locations)
        strengths = self.normalize_auth_strengths(raw_strengths)
        roles = self.normalize_groups(raw_roles, object_type="directoryRole")

        # Resolve group display names referenced in policy conditions
        group_ids = self._extract_group_ids(raw_policies)
        groups: list[DirectoryGroup] = []
        for gid in group_ids:
            raw_group = await self.fetch_group(token, gid)
            if raw_group:
                groups.extend(self.normalize_groups([raw_group], object_type="group"))

        all_directory_entries = roles + groups

        # Build coverage cache
        coverage = self.build_coverage_entries(policies)
        # Enrich display names from directory entries
        dir_map = {d.id: d.display_name for d in all_directory_entries}
        for entry in coverage:
            if entry.entity_id in dir_map:
                entry.entity_display_name = dir_map[entry.entity_id]
            elif entry.entity_id in (ALL_USERS, ALL_APPLICATIONS):
                entry.entity_display_name = entry.entity_id

        # Persist – full replace strategy
        from app.models.database import (
            AuthenticationStrength as ASModel,
            ConditionalAccessPolicy as CAPModel,
            DirectoryGroup as DGModel,
            NamedLocation as NLModel,
            PolicyCoverageCache as PCCModel,
        )

        db.query(PCCModel).delete()
        db.query(CAPModel).delete()
        db.query(NLModel).delete()
        db.query(ASModel).delete()
        db.query(DGModel).delete()
        db.flush()

        db.add_all(policies)
        db.add_all(locations)
        db.add_all(strengths)
        db.add_all(all_directory_entries)
        db.add_all(coverage)
        db.commit()

        counts = {
            "policies": len(policies),
            "named_locations": len(locations),
            "auth_strengths": len(strengths),
            "directory_entries": len(all_directory_entries),
            "coverage_entries": len(coverage),
        }
        logger.info("CA policy sync complete: %s", counts)
        return counts

    @staticmethod
    def _extract_group_ids(raw_policies: list[dict[str, Any]]) -> set[str]:
        """Gather unique group IDs referenced in policy conditions."""
        ids: set[str] = set()
        for p in raw_policies:
            cond = p.get("conditions", {}) or {}
            users = cond.get("users", {}) or {}
            for key in ("includeGroups", "excludeGroups"):
                for gid in users.get(key, []) or []:
                    if gid not in (ALL_USERS, NONE):
                        ids.add(gid)
        return ids


def _retry_after(response: httpx.Response) -> float:
    """Extract Retry-After header or default to 30 seconds."""
    try:
        return float(response.headers.get("Retry-After", "30"))
    except (ValueError, TypeError):
        return 30.0
