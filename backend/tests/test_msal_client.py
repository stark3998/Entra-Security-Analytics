"""Tests for the MSAL auth client."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from app.auth.msal_client import (
    MSALAuthClient,
    TokenAcquisitionError,
    get_auth_client,
    reset_auth_client,
)


@pytest.fixture()
def auth_client(settings, mock_msal):
    """Return a fresh MSALAuthClient using the mock MSAL CCA."""
    reset_auth_client()
    with patch("app.config._settings", settings):
        cli = MSALAuthClient()
    return cli


class TestMSALAuthClient:
    """Unit tests for MSALAuthClient."""

    def test_get_graph_token_success(self, auth_client, mock_msal):
        token = auth_client.get_graph_token()
        assert token == "fake-access-token"
        mock_msal.acquire_token_for_client.assert_called_once()

    def test_get_graph_token_failure(self, auth_client, mock_msal):
        mock_msal.acquire_token_for_client.return_value = {
            "error": "invalid_client",
            "error_description": "Bad credentials",
        }
        with pytest.raises(TokenAcquisitionError, match="invalid_client"):
            auth_client.get_graph_token()

    def test_get_o365_mgmt_token_success(self, auth_client, mock_msal):
        token = auth_client.get_o365_mgmt_token()
        assert token == "fake-access-token"

    def test_get_o365_mgmt_token_failure(self, auth_client, mock_msal):
        mock_msal.acquire_token_for_client.return_value = {
            "error": "unauthorized_client",
            "error_description": "Not authorized",
        }
        with pytest.raises(TokenAcquisitionError):
            auth_client.get_o365_mgmt_token()

    def test_get_auth_client_singleton(self, settings, mock_msal):
        reset_auth_client()
        with patch("app.config._settings", settings):
            c1 = get_auth_client()
            c2 = get_auth_client()
        assert c1 is c2
        reset_auth_client()

    def test_reset_clears_singleton(self, settings, mock_msal):
        reset_auth_client()
        with patch("app.config._settings", settings):
            c1 = get_auth_client()
            reset_auth_client()
            c2 = get_auth_client()
        assert c1 is not c2
        reset_auth_client()
