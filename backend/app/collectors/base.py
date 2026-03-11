"""Abstract base collector with retry, rate-limit handling, and pagination."""

from __future__ import annotations

import abc
import asyncio
import json
import logging
from datetime import datetime
from typing import Any, TypeVar

import httpx

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Retry configuration
MAX_RETRIES = 5
INITIAL_BACKOFF_SECONDS = 1.0
BACKOFF_MULTIPLIER = 2.0
RATE_LIMIT_STATUS = 429
SERVER_ERROR_THRESHOLD = 500


class CollectorError(Exception):
    """Raised when a collector encounters an unrecoverable error."""


class BaseCollector(abc.ABC):
    """Abstract base for all log collectors.

    Subclasses implement `_fetch_page` and `normalize`.
    The base class provides retry with exponential backoff,
    rate-limit (429) handling, and paginated iteration.
    """

    def __init__(self, http_client: httpx.AsyncClient | None = None) -> None:
        self._client = http_client or httpx.AsyncClient(timeout=30.0)
        self._owns_client = http_client is None

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # ── Abstract interface ─────────────────────────────────────

    @abc.abstractmethod
    async def _fetch_page(
        self,
        token: str,
        since: datetime,
        until: datetime,
        next_link: str | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Fetch one page of raw log entries.

        Returns:
            Tuple of (records, next_page_url_or_None).
        """
        ...

    @abc.abstractmethod
    def normalize(self, raw_records: list[dict[str, Any]]) -> list[Any]:
        """Convert raw API records into SQLAlchemy model instances."""
        ...

    @property
    @abc.abstractmethod
    def collector_name(self) -> str:
        """Unique name for this collector (used in CollectorState)."""
        ...

    # ── Paginated collection with retry ────────────────────────

    # Maximum time (seconds) for the entire collect() call across all pages
    COLLECTION_TIMEOUT_SECONDS: float = 300.0  # 5 minutes

    async def collect(
        self,
        token: str,
        since: datetime,
        until: datetime,
    ) -> list[dict[str, Any]]:
        """Collect all pages of log data for the given time range."""
        try:
            return await asyncio.wait_for(
                self._collect_all_pages(token, since, until),
                timeout=self.COLLECTION_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            raise CollectorError(
                f"[{self.collector_name}] Collection timed out after "
                f"{self.COLLECTION_TIMEOUT_SECONDS}s"
            )

    async def _collect_all_pages(
        self,
        token: str,
        since: datetime,
        until: datetime,
    ) -> list[dict[str, Any]]:
        """Internal: paginated collection loop."""
        all_records: list[dict[str, Any]] = []
        next_link: str | None = None
        page = 0

        while True:
            page += 1
            records, next_link = await self._fetch_with_retry(
                token, since, until, next_link
            )
            all_records.extend(records)
            logger.info(
                "[%s] Page %d: fetched %d records (total: %d)",
                self.collector_name,
                page,
                len(records),
                len(all_records),
            )
            if not next_link:
                break

        logger.info(
            "[%s] Collection complete: %d total records",
            self.collector_name,
            len(all_records),
        )
        return all_records

    async def _fetch_with_retry(
        self,
        token: str,
        since: datetime,
        until: datetime,
        next_link: str | None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Fetch a single page with exponential backoff retry."""
        backoff = INITIAL_BACKOFF_SECONDS

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                return await self._fetch_page(token, since, until, next_link)
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if status == RATE_LIMIT_STATUS:
                    retry_after = self._get_retry_after(exc.response)
                    logger.warning(
                        "[%s] Rate limited (429). Waiting %.1fs (attempt %d/%d)",
                        self.collector_name,
                        retry_after,
                        attempt,
                        MAX_RETRIES,
                    )
                    await asyncio.sleep(retry_after)
                elif status >= SERVER_ERROR_THRESHOLD:
                    logger.warning(
                        "[%s] Server error %d. Retrying in %.1fs (attempt %d/%d)",
                        self.collector_name,
                        status,
                        backoff,
                        attempt,
                        MAX_RETRIES,
                    )
                    await asyncio.sleep(backoff)
                    backoff *= BACKOFF_MULTIPLIER
                else:
                    detail = exc.response.text
                    if status == 401:
                        hint = (
                            " — Ensure the app registration has the required API "
                            "permissions AND that admin consent has been granted "
                            "(Entra ID → App registrations → API permissions → "
                            "Grant admin consent)."
                        )
                        detail += hint
                    raise CollectorError(
                        f"[{self.collector_name}] HTTP {status}: {detail}"
                    ) from exc
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as exc:
                logger.warning(
                    "[%s] Network error: %s. Retrying in %.1fs (attempt %d/%d)",
                    self.collector_name,
                    str(exc),
                    backoff,
                    attempt,
                    MAX_RETRIES,
                )
                await asyncio.sleep(backoff)
                backoff *= BACKOFF_MULTIPLIER

        raise CollectorError(
            f"[{self.collector_name}] Max retries ({MAX_RETRIES}) exceeded"
        )

    @staticmethod
    def _get_retry_after(response: httpx.Response) -> float:
        """Extract Retry-After header or default to 30 seconds."""
        try:
            return float(response.headers.get("Retry-After", "30"))
        except (ValueError, TypeError):
            return 30.0

    # ── Helpers ────────────────────────────────────────────────

    async def _get(
        self, url: str, token: str, params: dict[str, str] | None = None
    ) -> httpx.Response:
        """Send authenticated GET request."""
        response = await self._client.get(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            params=params,
        )
        response.raise_for_status()

        # Log the raw JSON response (truncated to avoid flooding)
        try:
            body = response.json()
            record_count = len(body.get("value", [])) if isinstance(body, dict) else "N/A"
            preview = json.dumps(body, indent=2, default=str)
            max_len = 4000
            if len(preview) > max_len:
                preview = preview[:max_len] + f"\n... (truncated, {len(preview)} chars total)"
            logger.debug(
                "[%s] API response from %s — %s records:\n%s",
                self.collector_name,
                url.split("?")[0],
                record_count,
                preview,
            )
        except Exception:
            logger.debug(
                "[%s] API response from %s (non-JSON, %d bytes)",
                self.collector_name,
                url.split("?")[0],
                len(response.content),
            )

        return response
