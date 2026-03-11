/**
 * AuthProvider — React context that wraps MSAL.js and exposes
 * authentication state + helpers to the entire application.
 *
 * Behaviour by auth_mode:
 *  - "client_credentials"  → no interactive login; all API calls are unprotected
 *  - "interactive"         → user must sign in; token attached to every request
 *  - "both"                → user can sign in; token attached when logged in
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import {
  PublicClientApplication,
  InteractionRequiredAuthError,
  AccountInfo,
  EventType,
} from "@azure/msal-browser";
import { MsalProvider, useMsal } from "@azure/msal-react";

import {
  AuthConfigResponse,
  buildMsalConfig,
  fetchAuthConfig,
  loginRequest,
} from "./msalConfig";
import { setTokenGetter } from "../api";

/* ── Context shape ─────────────────────────────────────────── */

export interface AuthContextValue {
  /** Current auth mode from backend */
  authMode: AuthConfigResponse["auth_mode"];
  /** Whether interactive auth is active (mode is "interactive" or "both") */
  isInteractiveMode: boolean;
  /** Currently signed-in account (null when not logged in) */
  account: AccountInfo | null;
  /** True while we're loading the initial auth config */
  loading: boolean;
  /** Sign in via popup */
  login: () => Promise<void>;
  /** Sign out */
  logout: () => Promise<void>;
  /** Acquire an access token silently (falls back to popup) */
  getAccessToken: () => Promise<string | null>;
}

const AuthContext = createContext<AuthContextValue>({
  authMode: "client_credentials",
  isInteractiveMode: false,
  account: null,
  loading: true,
  login: async () => {},
  logout: async () => {},
  getAccessToken: async () => null,
});

export const useAuth = () => useContext(AuthContext);

/* ── Inner provider (lives inside MsalProvider) ────────────── */

function InnerAuthProvider({
  authMode,
  children,
}: {
  authMode: AuthConfigResponse["auth_mode"];
  children: React.ReactNode;
}) {
  const { instance, accounts } = useMsal();
  const account = accounts[0] ?? null;

  const isInteractiveMode = authMode === "interactive" || authMode === "both";

  const login = useCallback(async () => {
    try {
      await instance.loginPopup(loginRequest);
    } catch (err) {
      console.error("Login failed:", err);
    }
  }, [instance]);

  const logout = useCallback(async () => {
    try {
      await instance.logoutPopup({ postLogoutRedirectUri: window.location.origin });
    } catch (err) {
      console.error("Logout failed:", err);
    }
  }, [instance]);

  const getAccessToken = useCallback(async (): Promise<string | null> => {
    if (!isInteractiveMode || !account) return null;

    try {
      const result = await instance.acquireTokenSilent({
        ...loginRequest,
        account,
      });
      return result.accessToken;
    } catch (err) {
      if (err instanceof InteractionRequiredAuthError) {
        try {
          const result = await instance.acquireTokenPopup(loginRequest);
          return result.accessToken;
        } catch (popupErr) {
          console.error("Token acquisition via popup failed:", popupErr);
          return null;
        }
      }
      console.error("Silent token acquisition failed:", err);
      return null;
    }
  }, [instance, account, isInteractiveMode]);

  const value = useMemo<AuthContextValue>(
    () => ({
      authMode,
      isInteractiveMode,
      account,
      loading: false,
      login,
      logout,
      getAccessToken,
    }),
    [authMode, isInteractiveMode, account, login, logout, getAccessToken],
  );

  // Register token getter so api.ts can attach Authorization header
  useEffect(() => {
    setTokenGetter(getAccessToken);
    return () => setTokenGetter(null);
  }, [getAccessToken]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

/* ── Outer provider (bootstraps MSAL instance) ─────────────── */

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [msalInstance, setMsalInstance] = useState<PublicClientApplication | null>(null);
  const [authMode, setAuthMode] = useState<AuthConfigResponse["auth_mode"]>("client_credentials");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function init() {
      try {
        const cfg = await fetchAuthConfig();

        if (cancelled) return;
        setAuthMode(cfg.auth_mode);

        if (cfg.auth_mode === "interactive" || cfg.auth_mode === "both") {
          const msalConfig = buildMsalConfig(cfg);
          const pca = new PublicClientApplication(msalConfig);
          await pca.initialize();

          // Set active account from cache if available
          const accounts = pca.getAllAccounts();
          if (accounts.length > 0) {
            pca.setActiveAccount(accounts[0]);
          }

          // Listen for login success to set active account
          pca.addEventCallback((event) => {
            if (
              event.eventType === EventType.LOGIN_SUCCESS &&
              event.payload &&
              "account" in event.payload
            ) {
              pca.setActiveAccount(event.payload.account as AccountInfo);
            }
          });

          if (!cancelled) setMsalInstance(pca);
        }
      } catch (err) {
        if (!cancelled) {
          console.error("Auth initialization failed:", err);
          setError(err instanceof Error ? err.message : "Auth init failed");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    init();
    return () => {
      cancelled = true;
    };
  }, []);

  // Loading state
  if (loading) {
    return (
      <div className="auth-loading">
        <p>Initializing authentication...</p>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="auth-error">
        <p>Authentication error: {error}</p>
        <button onClick={() => window.location.reload()}>Retry</button>
      </div>
    );
  }

  // Client-credentials mode: no MSAL needed
  if (authMode === "client_credentials" || !msalInstance) {
    const noopValue: AuthContextValue = {
      authMode,
      isInteractiveMode: false,
      account: null,
      loading: false,
      login: async () => {},
      logout: async () => {},
      getAccessToken: async () => null,
    };
    return (
      <AuthContext.Provider value={noopValue}>{children}</AuthContext.Provider>
    );
  }

  // Interactive / Both mode: wrap with MsalProvider
  return (
    <MsalProvider instance={msalInstance}>
      <InnerAuthProvider authMode={authMode}>{children}</InnerAuthProvider>
    </MsalProvider>
  );
}

export default AuthProvider;
