/**
 * MSAL.js configuration for Entra ID interactive authentication.
 *
 * The configuration is bootstrapped from the backend `/api/auth/config`
 * endpoint so that clientId and authority stay in sync with server settings.
 */

import { Configuration, LogLevel } from "@azure/msal-browser";

/* ── Types ─────────────────────────────────────────────────── */

export interface AuthConfigResponse {
  auth_mode: "client_credentials" | "interactive" | "both";
  authority: string;
  client_id: string;
  redirect_uri: string;
  scopes: string[];
}

/* ── Fetch bootstrap config from backend ───────────────────── */

let _cachedConfig: AuthConfigResponse | null = null;

export async function fetchAuthConfig(): Promise<AuthConfigResponse> {
  if (_cachedConfig) return _cachedConfig;

  const resp = await fetch("/api/auth/config");
  if (!resp.ok) {
    throw new Error(`Failed to fetch auth config: ${resp.status}`);
  }
  _cachedConfig = (await resp.json()) as AuthConfigResponse;
  return _cachedConfig;
}

export function clearAuthConfigCache(): void {
  _cachedConfig = null;
}

/* ── Build MSAL Configuration from backend response ───────── */

export function buildMsalConfig(cfg: AuthConfigResponse): Configuration {
  return {
    auth: {
      clientId: cfg.client_id,
      authority: cfg.authority,
      redirectUri: cfg.redirect_uri,
      postLogoutRedirectUri: window.location.origin,
      navigateToLoginRequestUrl: true,
    },
    cache: {
      cacheLocation: "sessionStorage",
      storeAuthStateInCookie: false,
    },
    system: {
      loggerOptions: {
        logLevel: LogLevel.Warning,
        piiLoggingEnabled: false,
      },
    },
  };
}

/* ── Login request scopes ──────────────────────────────────── */

export const loginRequest = {
  scopes: ["openid", "profile", "User.Read"],
};
