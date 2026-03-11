import { useQuery } from "@tanstack/react-query";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from "recharts";
import {
  fetchDashboardSummary,
  fetchLogVolume,
  fetchRiskScores,
  type DashboardSummary,
  type LogVolumes,
  type RiskScore,
} from "../api";

export default function Dashboard() {
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
                  <tr key={u.user_id}>
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
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
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
