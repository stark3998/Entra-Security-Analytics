/**
 * Settings page — manage authentication mode and app registration details.
 *
 * Allows switching between:
 *  - Client Credentials (daemon mode, app registration required)
 *  - Interactive (user signs in via Entra ID)
 *  - Both (hybrid — user login + background collection)
 */

import { useState, useEffect, useCallback } from "react";
import { useAuth } from "../auth/AuthProvider";
import { clearAuthConfigCache } from "../auth/msalConfig";
import {
  fetchSettings,
  updateSettings,
  SettingsResponse,
  SettingsUpdate,
} from "../api";

export default function Settings() {
  const { authMode: currentAuthMode, account } = useAuth();

  const [settings, setSettings] = useState<SettingsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Form state
  const [authMode, setAuthMode] = useState("client_credentials");
  const [tenantId, setTenantId] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [frontendClientId, setFrontendClientId] = useState("");
  const [jwtAudience, setJwtAudience] = useState("");

  const loadSettings = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await fetchSettings();
      setSettings(data);
      setAuthMode(data.auth_mode);
      setTenantId(data.azure_tenant_id);
      setClientId(data.azure_client_id);
      setFrontendClientId(data.frontend_client_id);
      setJwtAudience(data.jwt_audience);
      setClientSecret(""); // Never pre-fill secrets
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load settings");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setSaving(true);

    try {
      const payload: SettingsUpdate = { auth_mode: authMode };

      // Only send credential fields if they have values
      if (tenantId) payload.azure_tenant_id = tenantId;
      if (clientId) payload.azure_client_id = clientId;
      if (clientSecret) payload.azure_client_secret = clientSecret;
      if (frontendClientId) payload.frontend_client_id = frontendClientId;
      if (jwtAudience) payload.jwt_audience = jwtAudience;

      const updated = await updateSettings(payload);
      setSettings(updated);
      setClientSecret("");
      clearAuthConfigCache();
      setSuccess(
        "Settings saved. If you changed auth mode, please reload the page for changes to take effect."
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save settings");
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <p>Loading settings...</p>;

  const needsClientCreds = authMode === "client_credentials" || authMode === "both";
  const needsInteractive = authMode === "interactive" || authMode === "both";

  return (
    <div className="settings-page">
      <h2>Settings</h2>

      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      {/* Current status */}
      <section className="settings-section">
        <h3>Current Status</h3>
        <div className="status-grid">
          <div className="status-item">
            <span className="status-label">Auth Mode:</span>
            <span className="status-value badge">{currentAuthMode}</span>
          </div>
          <div className="status-item">
            <span className="status-label">Client Credentials:</span>
            <span
              className={`status-value badge ${settings?.client_credentials_configured ? "badge-ok" : "badge-warn"}`}
            >
              {settings?.client_credentials_configured ? "Configured" : "Not configured"}
            </span>
          </div>
          <div className="status-item">
            <span className="status-label">Interactive Auth:</span>
            <span
              className={`status-value badge ${settings?.interactive_auth_enabled ? "badge-ok" : "badge-warn"}`}
            >
              {settings?.interactive_auth_enabled ? "Enabled" : "Disabled"}
            </span>
          </div>
          <div className="status-item">
            <span className="status-label">Signed In:</span>
            <span className="status-value">
              {account ? account.name ?? account.username : "Not signed in"}
            </span>
          </div>
          <div className="status-item">
            <span className="status-label">Available Collectors:</span>
            <span className="status-value">
              {settings?.available_collectors.length
                ? settings.available_collectors.join(", ")
                : "None"}
            </span>
          </div>
        </div>
      </section>

      {/* Settings form */}
      <form onSubmit={handleSave}>
        <section className="settings-section">
          <h3>Authentication Mode</h3>
          <div className="radio-group">
            <label className="radio-label">
              <input
                type="radio"
                name="authMode"
                value="client_credentials"
                checked={authMode === "client_credentials"}
                onChange={(e) => setAuthMode(e.target.value)}
              />
              <div>
                <strong>Client Credentials (Daemon)</strong>
                <p className="radio-desc">
                  Background log collection using app registration. No user sign-in required.
                </p>
              </div>
            </label>

            <label className="radio-label">
              <input
                type="radio"
                name="authMode"
                value="interactive"
                checked={authMode === "interactive"}
                onChange={(e) => setAuthMode(e.target.value)}
              />
              <div>
                <strong>Interactive (User Sign-In)</strong>
                <p className="radio-desc">
                  Users sign in via Entra ID. Graph API logs collected using delegated permissions.
                  O365 Management API not available in this mode.
                </p>
              </div>
            </label>

            <label className="radio-label">
              <input
                type="radio"
                name="authMode"
                value="both"
                checked={authMode === "both"}
                onChange={(e) => setAuthMode(e.target.value)}
              />
              <div>
                <strong>Both (Hybrid)</strong>
                <p className="radio-desc">
                  User sign-in for dashboard access + background collection via app registration
                  for all log sources.
                </p>
              </div>
            </label>
          </div>
        </section>

        {/* Client credentials section */}
        {needsClientCreds && (
          <section className="settings-section">
            <h3>App Registration (Client Credentials)</h3>
            <p className="section-desc">
              Required for background log collection. Register an app in Azure Entra ID with
              appropriate API permissions.
            </p>

            <div className="form-group">
              <label htmlFor="tenantId">Tenant ID</label>
              <input
                id="tenantId"
                type="text"
                value={tenantId}
                onChange={(e) => setTenantId(e.target.value)}
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              />
            </div>

            <div className="form-group">
              <label htmlFor="clientId">Client ID</label>
              <input
                id="clientId"
                type="text"
                value={clientId}
                onChange={(e) => setClientId(e.target.value)}
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              />
            </div>

            <div className="form-group">
              <label htmlFor="clientSecret">Client Secret</label>
              <input
                id="clientSecret"
                type="password"
                value={clientSecret}
                onChange={(e) => setClientSecret(e.target.value)}
                placeholder={
                  settings?.has_client_secret
                    ? "••••••••  (leave blank to keep current)"
                    : "Enter client secret"
                }
              />
              {settings?.has_client_secret && (
                <span className="form-hint">A secret is already configured.</span>
              )}
            </div>
          </section>
        )}

        {/* Interactive auth section */}
        {needsInteractive && (
          <section className="settings-section">
            <h3>Interactive Authentication</h3>
            <p className="section-desc">
              Configure the SPA app registration for user sign-in. This should be a separate
              app registration with &quot;Single-page application&quot; redirect URI.
            </p>

            <div className="form-group">
              <label htmlFor="frontendClientId">Frontend Client ID (SPA)</label>
              <input
                id="frontendClientId"
                type="text"
                value={frontendClientId}
                onChange={(e) => setFrontendClientId(e.target.value)}
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (or leave blank to reuse backend Client ID)"
              />
              <span className="form-hint">
                If left blank, the backend Client ID will be used (must have SPA redirect URI
                configured).
              </span>
            </div>

            <div className="form-group">
              <label htmlFor="jwtAudience">JWT Audience</label>
              <input
                id="jwtAudience"
                type="text"
                value={jwtAudience}
                onChange={(e) => setJwtAudience(e.target.value)}
                placeholder={`api://<client-id> or leave blank for default`}
              />
              <span className="form-hint">
                The expected audience claim in the JWT. Defaults to the frontend Client ID.
              </span>
            </div>
          </section>
        )}

        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={saving}>
            {saving ? "Saving..." : "Save Settings"}
          </button>
          <button
            type="button"
            className="btn btn-outline"
            onClick={loadSettings}
            disabled={saving}
          >
            Reset
          </button>
        </div>
      </form>
    </div>
  );
}
