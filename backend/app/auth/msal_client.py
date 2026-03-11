"""MSAL authentication for Microsoft Graph and O365 Management API.

Supports both client-credentials (daemon) and delegated (interactive) flows.
"""

from __future__ import annotations

import logging
from typing import Any

import msal

from app.config import get_settings

logger = logging.getLogger(__name__)

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
O365_MGMT_SCOPE = "https://manage.office.com/.default"


class MSALAuthClient:
    """Wrapper around MSAL ConfidentialClientApplication.

    Acquires and caches tokens for two resource scopes:
    - Microsoft Graph (Entra sign-in & audit logs)
    - Office 365 Management API (O365, SharePoint, Power Apps logs)

    When client_secret is empty the client-credentials flow is unavailable;
    only delegated (pass-through) tokens can be used.
    """

    def __init__(
        self,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> None:
        settings = get_settings()
        self._tenant_id = tenant_id or settings.azure_tenant_id
        self._client_id = client_id or settings.azure_client_id
        self._client_secret = client_secret or settings.azure_client_secret

        self._app: msal.ConfidentialClientApplication | None = None
        if self._client_id and self._client_secret and self._tenant_id:
            authority = f"https://login.microsoftonline.com/{self._tenant_id}"
            self._app = msal.ConfidentialClientApplication(
                client_id=self._client_id,
                client_credential=self._client_secret,
                authority=authority,
            )
            logger.info("MSAL client initialised for tenant %s", self._tenant_id)
        else:
            logger.warning(
                "MSAL client created without full credentials – "
                "client-credentials flow unavailable"
            )

    # ── Client-credentials flow ───────────────────────────────

    @property
    def is_configured(self) -> bool:
        """True when app-registration credentials are present."""
        return self._app is not None

    def _acquire_token(self, scopes: list[str]) -> str:
        """Acquire token via client-credentials flow with MSAL cache."""
        if not self._app:
            raise TokenAcquisitionError(
                "Client-credentials flow unavailable – no app registration configured"
            )
        # Try cache first
        result: dict[str, Any] | None = self._app.acquire_token_silent(
            scopes=scopes, account=None
        )
        if result and "access_token" in result:
            logger.debug("Token cache hit for scope %s", scopes[0])
            return result["access_token"]

        # Cache miss – acquire new token
        result = self._app.acquire_token_for_client(scopes=scopes)
        if result and "access_token" in result:
            logger.debug("Acquired new token for scope %s", scopes[0])
            return result["access_token"]

        error = result.get("error", "unknown") if result else "no_result"
        error_desc = result.get("error_description", "") if result else ""
        msg = f"Token acquisition failed for {scopes[0]}: {error} – {error_desc}"
        logger.error(msg)
        raise TokenAcquisitionError(msg)

    def get_graph_token(self) -> str:
        """Get access token for Microsoft Graph API (client-credentials)."""
        return self._acquire_token([GRAPH_SCOPE])

    def get_o365_mgmt_token(self) -> str:
        """Get access token for Office 365 Management Activity API."""
        return self._acquire_token([O365_MGMT_SCOPE])

    @property
    def tenant_id(self) -> str:
        return self._tenant_id


class TokenAcquisitionError(Exception):
    """Raised when MSAL cannot acquire a token."""


# ── Module-level singleton ─────────────────────────────────────
_client: MSALAuthClient | None = None


def get_auth_client() -> MSALAuthClient:
    """Return the cached MSAL auth client singleton."""
    global _client  # noqa: PLW0603
    if _client is None:
        _client = MSALAuthClient()
    return _client


def reset_auth_client() -> None:
    """Reset cached client (useful in tests)."""
    global _client  # noqa: PLW0603
    _client = None
