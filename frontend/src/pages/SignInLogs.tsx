import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchSignInLogs, type SignInLog, type PaginatedResponse } from "../api";
import SyncStatusPanel from "../components/SyncStatusPanel";
import SortableTable, { type ColumnDef } from "../components/SortableTable";

const PAGE_SIZE = 50;

const columns: ColumnDef<SignInLog>[] = [
  {
    key: "created_datetime",
    header: "Time",
    value: (r) => r.created_datetime,
    render: (r) => fmtDate(r.created_datetime),
  },
  {
    key: "user",
    header: "User",
    groupable: true,
    value: (r) => r.user_display_name || r.user_principal_name,
    render: (r) => (
      <span title={r.user_principal_name}>
        {r.user_display_name || r.user_principal_name}
      </span>
    ),
  },
  {
    key: "app",
    header: "App",
    groupable: true,
    value: (r) => r.app_display_name,
  },
  {
    key: "ip",
    header: "IP",
    groupable: true,
    value: (r) => r.ip_address,
  },
  {
    key: "location",
    header: "Location",
    groupable: true,
    value: (r) => [r.location_city, r.location_country].filter(Boolean).join(", "),
  },
  {
    key: "risk",
    header: "Risk",
    groupable: true,
    value: (r) => r.risk_level_during_signin,
    render: (r) => <RiskBadge level={r.risk_level_during_signin} />,
  },
  {
    key: "status",
    header: "Status",
    groupable: true,
    value: (r) => r.status_error_code,
    render: (r) => (r.status_error_code === 0 ? "✓" : `✗ ${r.status_error_code}`),
  },
  {
    key: "ca",
    header: "CA",
    groupable: true,
    value: (r) => r.conditional_access_status,
  },
];

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
        <p className="page-subtitle">Entra ID authentication events — filter by user, risk level, and sign-in status</p>
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
          <SortableTable
            columns={columns}
            data={items}
            rowKey={(r) => r.id}
            defaultSort={{ key: "created_datetime", dir: "desc" }}
          />
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
