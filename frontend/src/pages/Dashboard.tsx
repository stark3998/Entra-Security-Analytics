import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from "recharts";
import {
  fetchDashboardSummary,
  fetchLogVolume,
  fetchRiskScores,
  fetchEvent,
  type DashboardSummary,
  type LogVolumes,
  type RiskScore,
  type WindowDetail,
  type EventLookupResult,
} from "../api";
import JsonView from "../components/JsonView";

export default function Dashboard() {
  const [expandedUser, setExpandedUser] = useState<string | null>(null);

  const summary = useQuery<DashboardSummary>({
    queryKey: ["dashboard-summary"],
    queryFn: fetchDashboardSummary,
  });
  const volume = useQuery<LogVolumes>({
    queryKey: ["log-volume"],
    queryFn: () => fetchLogVolume(7),
  });
  const risk = useQuery<{ users: RiskScore[] }>({
    queryKey: ["risk-scores"],
    queryFn: () => fetchRiskScores(0),
  });

  const kpis = summary.data;
  const volumeData = volume.data
    ? Object.entries(volume.data.volumes).map(([source, count]) => ({
        source,
        count,
      }))
    : [];

  const highRiskUsers = (risk.data?.users ?? [])
    .filter((u) => u.score >= 50)
    .sort((a, b) => b.score - a.score)
    .slice(0, 10);

  return (
    <div>
      <h1 className="page-heading">Dashboard</h1>

      {/* KPI strip */}
      <div className="kpi-strip">
        <KPI label="Open Incidents" value={kpis?.open_incidents} />
        <KPI label="Critical (24h)" value={kpis?.critical_incidents_24h} />
        <KPI label="Incidents (7d)" value={kpis?.incidents_7d} />
        <KPI label="Watch Windows" value={kpis?.active_watch_windows} />
        <KPI label="Sign-Ins (24h)" value={kpis?.signin_events_24h} />
      </div>

      {/* Log volume chart */}
      <div className="card" style={{ marginBottom: "1.5rem" }}>
        <h2>Log Volume (Last 7 Days)</h2>
        {volume.isLoading ? (
          <p className="loading">Loading…</p>
        ) : (
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={volumeData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="source" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="count" fill="#5b8dfa" name="Events" />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* High-risk users */}
      <div className="card">
        <h2>High-Risk Users</h2>
        {risk.isLoading ? (
          <p className="loading">Loading…</p>
        ) : highRiskUsers.length === 0 ? (
          <p style={{ color: "var(--text-secondary)" }}>No high-risk users at this time.</p>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th></th>
                  <th>User</th>
                  <th>Score</th>
                  <th>Base Risk</th>
                  <th>Entra Risk</th>
                  <th>Multiplier</th>
                  <th>Windows</th>
                </tr>
              </thead>
              <tbody>
                {highRiskUsers.map((u) => (
                  <RiskUserRow
                    key={u.user_id}
                    user={u}
                    isExpanded={expandedUser === u.user_id}
                    onToggle={() => setExpandedUser(expandedUser === u.user_id ? null : u.user_id)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

/* ── Risk User Row (expandable) ─────────────────────────── */

function RiskUserRow({
  user: u,
  isExpanded,
  onToggle,
}: {
  user: RiskScore;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  return (
    <>
      <tr className="clickable-row" onClick={onToggle}>
        <td className="expand-arrow">{isExpanded ? "▼" : "▶"}</td>
        <td>{u.user_id}</td>
        <td>
          <span className={`badge badge-${scoreSeverity(u.score)}`}>
            {u.score}
          </span>
        </td>
        <td>{u.base_risk}</td>
        <td>{u.entra_risk}</td>
        <td>{u.multiplier}×</td>
        <td>{u.active_windows}</td>
      </tr>
      {isExpanded && (
        <tr className="expanded-row">
          <td colSpan={7}>
            <RiskUserDetails user={u} />
          </td>
        </tr>
      )}
    </>
  );
}

/* ── Expanded risk details panel ───────────────────────── */

function RiskUserDetails({ user: u }: { user: RiskScore }) {
  const [expandedEvent, setExpandedEvent] = useState<string | null>(null);

  return (
    <div className="user-detail-panel">
      {/* Score breakdown */}
      <div className="risk-alert">
        <strong>Score Breakdown:</strong>
        <p style={{ margin: "0.5rem 0 0" }}>
          Final Score = min(100, (Base Risk + Entra Risk) × Multiplier)<br />
          <strong>{u.score}</strong> = min(100, ({u.base_risk} + {u.entra_risk}) × {u.multiplier})
        </p>
      </div>

      <div className="detail-grid">
        {/* Score components */}
        <div className="detail-section">
          <h4>Score Components</h4>
          <table className="nested-table">
            <tbody>
              <tr>
                <td><strong>Base Risk (from watch windows)</strong></td>
                <td>{u.base_risk} pts</td>
              </tr>
              <tr>
                <td><strong>Entra ID Risk</strong></td>
                <td>
                  {u.entra_risk} pts
                  {u.entra_risk_level && (
                    <span className={`badge badge-${u.entra_risk_level === "high" ? "critical" : u.entra_risk_level === "medium" ? "medium" : "info"}`} style={{ marginLeft: "0.5rem" }}>
                      {u.entra_risk_level}
                    </span>
                  )}
                </td>
              </tr>
              <tr>
                <td><strong>Multiplier</strong></td>
                <td>
                  {u.multiplier}×
                  <span style={{ color: "var(--text-secondary)", marginLeft: "0.5rem" }}>
                    ({u.active_windows} active window{u.active_windows !== 1 ? "s" : ""})
                  </span>
                </td>
              </tr>
              <tr>
                <td><strong>Final Score</strong></td>
                <td>
                  <span className={`badge badge-${scoreSeverity(u.score)}`} style={{ fontSize: "1rem" }}>
                    {u.score} / 100
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        {/* Active watch windows */}
        <div className="detail-section" style={{ gridColumn: "1 / -1" }}>
          <h4>Active Watch Windows ({u.window_details.length})</h4>
          {u.window_details.length > 0 ? (
            <table className="nested-table">
              <thead>
                <tr>
                  <th></th>
                  <th>Rule</th>
                  <th>Risk Contribution</th>
                  <th>Started</th>
                  <th>Expires</th>
                  <th>Trigger Event</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {u.window_details.map((w, i) => (
                  <WatchWindowRow
                    key={i}
                    w={w}
                    isExpanded={expandedEvent === `${i}-${w.trigger_event_id}`}
                    onToggle={() => setExpandedEvent(
                      expandedEvent === `${i}-${w.trigger_event_id}` ? null : `${i}-${w.trigger_event_id}`
                    )}
                  />
                ))}
              </tbody>
            </table>
          ) : (
            <p style={{ color: "var(--text-secondary)" }}>No active watch windows.</p>
          )}
        </div>

        {/* Raw Risk Score JSON */}
        <div className="detail-section" style={{ gridColumn: "1 / -1" }}>
          <h4>Raw Risk Score JSON</h4>
          <JsonView data={u} initialExpanded={false} />
        </div>
      </div>
    </div>
  );
}

/* ── Watch Window Row (expandable trigger event) ───────── */

function WatchWindowRow({
  w,
  isExpanded,
  onToggle,
}: {
  w: WindowDetail;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  return (
    <>
      <tr className="clickable-row" onClick={onToggle}>
        <td className="expand-arrow">{isExpanded ? "▼" : "▶"}</td>
        <td>
          <div>
            <a
              href={`/rules`}
              onClick={(e) => e.stopPropagation()}
              title={w.rule_slug || `Rule #${w.rule_id}`}
              style={{ color: "var(--accent)", textDecoration: "none" }}
            >
              {w.rule_name || w.rule_slug || `Rule #${w.rule_id}`}
            </a>
            {w.rule_description && (
              <div style={{ color: "var(--text-secondary)", fontSize: "0.8rem", marginTop: "0.15rem" }}>
                {w.rule_description}
              </div>
            )}
          </div>
        </td>
        <td>{w.risk_contribution} pts</td>
        <td>{w.window_start ? new Date(w.window_start).toLocaleString() : "–"}</td>
        <td>{new Date(w.window_end).toLocaleString()}</td>
        <td style={{ fontFamily: "monospace", fontSize: "0.85rem" }}>
          {truncate(w.trigger_event_id, 24)}
        </td>
        <td><span className="badge badge-info">{w.trigger_event_source || "–"}</span></td>
      </tr>
      {isExpanded && (
        <tr className="expanded-row">
          <td colSpan={7}>
            <EventDetailPanel eventId={w.trigger_event_id} />
          </td>
        </tr>
      )}
    </>
  );
}

/* ── Inline event detail panel (fetches on expand) ─────── */

function EventDetailPanel({ eventId }: { eventId: string }) {
  const [viewMode, setViewMode] = useState<"table" | "raw">("table");
  const { data, isLoading, error } = useQuery<EventLookupResult>({
    queryKey: ["event-lookup", eventId],
    queryFn: () => fetchEvent(eventId),
  });

  if (isLoading) return <p className="loading" style={{ padding: "0.5rem" }}>Loading event…</p>;
  if (error) return <p style={{ color: "var(--danger)", padding: "0.5rem" }}>Event not found or error loading.</p>;
  if (!data) return null;

  const evt = data.event;
  const typeLabel = data.event_type === "signin" ? "Sign-In Log"
    : data.event_type === "audit" ? "Audit Log"
    : "Activity Log";

  // Separate scalar fields from object/array fields
  const scalarEntries = Object.entries(evt).filter(
    ([, v]) => v != null && v !== "" && typeof v !== "object"
  );
  const objectEntries = Object.entries(evt).filter(
    ([, v]) => v != null && typeof v === "object"
  );

  return (
    <div style={{ padding: "0.5rem 0" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.5rem" }}>
        <strong style={{ fontSize: "0.9rem" }}>
          {typeLabel}
          <span className="badge badge-info" style={{ marginLeft: "0.5rem" }}>{data.event_type}</span>
        </strong>
        <div style={{ display: "flex", gap: "0.25rem" }}>
          <button className={`btn btn-sm ${viewMode === "table" ? "btn-primary" : ""}`} onClick={() => setViewMode("table")}>Table</button>
          <button className={`btn btn-sm ${viewMode === "raw" ? "btn-primary" : ""}`} onClick={() => setViewMode("raw")}>Raw JSON</button>
        </div>
      </div>
      {viewMode === "table" ? (
        <table className="nested-table">
          <tbody>
            {scalarEntries.map(([key, value]) => (
              <tr key={key}>
                <td style={{ fontWeight: 600, whiteSpace: "nowrap", width: "1%" }}>{formatKey(key)}</td>
                <td style={{ wordBreak: "break-all" }}>{String(value)}</td>
              </tr>
            ))}
            {objectEntries.map(([key, value]) => (
              <tr key={key}>
                <td style={{ fontWeight: 600, whiteSpace: "nowrap", width: "1%", verticalAlign: "top" }}>{formatKey(key)}</td>
                <td><JsonView data={value} initialExpanded={false} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <JsonView data={evt} initialExpanded={true} />
      )}
    </div>
  );
}

function formatKey(key: string): string {
  return key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function truncate(s: string, max: number): string {
  if (!s) return "–";
  return s.length > max ? s.slice(0, max) + "…" : s;
}

function KPI({ label, value }: { label: string; value?: number }) {
  return (
    <div className="kpi-card">
      <div className="kpi-value">{value ?? "–"}</div>
      <div className="kpi-label">{label}</div>
    </div>
  );
}

function scoreSeverity(score: number): string {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  return "low";
}
