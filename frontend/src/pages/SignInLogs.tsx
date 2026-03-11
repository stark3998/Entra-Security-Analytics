import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchSignInLogs, type SignInLog, type PaginatedResponse } from "../api";
import SyncStatusPanel from "../components/SyncStatusPanel";

const PAGE_SIZE = 50;

export default function SignInLogs() {
  const [offset, setOffset] = useState(0);
  const [user, setUser] = useState("");
  const [riskLevel, setRiskLevel] = useState("");

  const params: Record<string, string> = {
    offset: String(offset),
    limit: String(PAGE_SIZE),
  };
  if (user) params.user = user;
  if (riskLevel) params.risk_level = riskLevel;

  const { data, isLoading, error } = useQuery<PaginatedResponse<SignInLog>>({
    queryKey: ["signin-logs", offset, user, riskLevel],
    queryFn: () => fetchSignInLogs(params),
  });

  const total = data?.total ?? 0;
  const items = data?.items ?? [];

  return (
    <div>
      <div className="page-header-row">
        <h1 className="page-heading">Sign-In Logs</h1>
        <SyncStatusPanel invalidateKeys={[["signin-logs"]]} />
      </div>

      <div className="filters">
        <input
          placeholder="Filter by user…"
          value={user}
          onChange={(e) => { setUser(e.target.value); setOffset(0); }}
        />
        <select
          value={riskLevel}
          onChange={(e) => { setRiskLevel(e.target.value); setOffset(0); }}
        >
          <option value="">All Risk Levels</option>
          <option value="none">None</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
        </select>
      </div>

      {error && <div className="error-box">{String(error)}</div>}

      <div className="card">
        {isLoading ? (
          <p className="loading">Loading…</p>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>User</th>
                  <th>App</th>
                  <th>IP</th>
                  <th>Location</th>
                  <th>Risk</th>
                  <th>Status</th>
                  <th>CA</th>
                </tr>
              </thead>
              <tbody>
                {items.map((r) => (
                  <tr key={r.id}>
                    <td>{fmtDate(r.created_datetime)}</td>
                    <td title={r.user_principal_name}>{r.user_display_name || r.user_principal_name}</td>
                    <td>{r.app_display_name}</td>
                    <td>{r.ip_address}</td>
                    <td>{[r.location_city, r.location_country].filter(Boolean).join(", ")}</td>
                    <td><RiskBadge level={r.risk_level_during_signin} /></td>
                    <td>{r.status_error_code === 0 ? "✓" : `✗ ${r.status_error_code}`}</td>
                    <td>{r.conditional_access_status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <Pagination offset={offset} total={total} pageSize={PAGE_SIZE} onChange={setOffset} />
      </div>
    </div>
  );
}

function RiskBadge({ level }: { level: string }) {
  const cls =
    level === "high" ? "badge-critical" :
    level === "medium" ? "badge-medium" :
    level === "low" ? "badge-low" : "badge-info";
  return <span className={`badge ${cls}`}>{level}</span>;
}

function Pagination({
  offset, total, pageSize, onChange,
}: { offset: number; total: number; pageSize: number; onChange: (o: number) => void }) {
  const page = Math.floor(offset / pageSize) + 1;
  const pages = Math.ceil(total / pageSize) || 1;
  return (
    <div className="pagination">
      <button disabled={offset === 0} onClick={() => onChange(offset - pageSize)}>← Prev</button>
      <span>Page {page} of {pages} ({total} total)</span>
      <button disabled={offset + pageSize >= total} onClick={() => onChange(offset + pageSize)}>Next →</button>
    </div>
  );
}

function fmtDate(iso: string | null): string {
  if (!iso) return "–";
  return new Date(iso).toLocaleString();
}
