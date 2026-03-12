import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
  PieChart, Pie, Cell,
} from "recharts";
import {
  fetchPIMStats,
  fetchPIMAssignments,
  fetchPIMEligibilities,
  fetchPIMActivations,
  fetchPIMAuditLogs,
  fetchPIMInsights,
  syncPIM,
  type PIMStats,
  type PIMAssignment,
  type PIMEligibility,
  type PIMActivation,
  type PIMAuditLog,
  type PIMInsights,
  type PaginatedResponse,
} from "../api";
import JsonView from "../components/JsonView";
import SortableTable, { type ColumnDef } from "../components/SortableTable";

const TABS = ["Overview", "Role Assignments", "Eligibilities", "Activations", "Audit Logs", "Insights"] as const;
type Tab = (typeof TABS)[number];

const PAGE_SIZE = 50;

export default function PIMDashboard() {
  const [tab, setTab] = useState<Tab>("Overview");
  const queryClient = useQueryClient();

  const syncMut = useMutation({
    mutationFn: syncPIM,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["pim"] });
    },
  });

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <h1 className="page-heading">Privileged Access Management</h1>
          <p className="page-subtitle">PIM role assignments, activations, eligibilities, and privileged access insights</p>
        </div>
        <button
          className="btn btn-primary"
          onClick={() => syncMut.mutate()}
          disabled={syncMut.isPending}
        >
          {syncMut.isPending ? "Syncing…" : "Sync from Graph"}
        </button>
      </div>

      {syncMut.isSuccess && (
        <div className="risk-alert" style={{ marginBottom: "1rem" }}>
          Sync complete: {Object.entries(syncMut.data.synced).map(([k, v]) => `${k}: ${v}`).join(", ")}
        </div>
      )}
      {syncMut.isError && (
        <div className="error-box" style={{ marginBottom: "1rem" }}>Sync failed: {String(syncMut.error)}</div>
      )}

      <div className="tab-bar">
        {TABS.map((t) => (
          <button key={t} className={`tab-btn ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>
            {t}
          </button>
        ))}
      </div>

      <div className="card">
        {tab === "Overview" && <OverviewTab />}
        {tab === "Role Assignments" && <AssignmentsTab />}
        {tab === "Eligibilities" && <EligibilitiesTab />}
        {tab === "Activations" && <ActivationsTab />}
        {tab === "Audit Logs" && <AuditLogsTab />}
        {tab === "Insights" && <InsightsTab />}
      </div>
    </div>
  );
}

/* ── Overview Tab ────────────────────────────────────────────── */

function OverviewTab() {
  const stats = useQuery<PIMStats>({
    queryKey: ["pim", "stats"],
    queryFn: fetchPIMStats,
  });
  const insights = useQuery<PIMInsights>({
    queryKey: ["pim", "insights"],
    queryFn: fetchPIMInsights,
  });

  const kpis = stats.data;
  const dist = insights.data?.role_distribution ?? [];
  const pieData = insights.data?.permanent_vs_timebound;

  return (
    <div>
      <div className="kpi-strip">
        <KPI label="Active Assignments" value={kpis?.total_assignments} />
        <KPI label="Eligible Assignments" value={kpis?.total_eligibilities} />
        <KPI label="Permanent" value={kpis?.permanent_assignments} warn={kpis ? kpis.permanent_assignments > 0 : false} />
        <KPI label="Activations (24h)" value={kpis?.activations_24h} />
        <KPI label="Activations (7d)" value={kpis?.activations_7d} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: "1.5rem", marginTop: "1.5rem" }}>
        <div className="card">
          <h3>Role Distribution (Active vs Eligible)</h3>
          {insights.isLoading ? (
            <p className="loading">Loading…</p>
          ) : dist.length === 0 ? (
            <p style={{ color: "var(--text-secondary)" }}>No data — sync PIM data first.</p>
          ) : (
            <ResponsiveContainer width="100%" height={Math.max(260, dist.length * 28)}>
              <BarChart data={dist} layout="vertical" margin={{ left: 160 }}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" />
                <YAxis dataKey="role" type="category" tick={{ fontSize: 12 }} width={150} />
                <Tooltip />
                <Legend />
                <Bar dataKey="active" fill="#5b8dfa" name="Active" stackId="a" />
                <Bar dataKey="eligible" fill="#f5a623" name="Eligible" stackId="a" />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="card">
          <h3>Permanent vs Time-Bound</h3>
          {!pieData ? (
            <p className="loading">Loading…</p>
          ) : pieData.permanent + pieData.time_bound === 0 ? (
            <p style={{ color: "var(--text-secondary)" }}>No assignment data.</p>
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie
                  data={[
                    { name: "Permanent", value: pieData.permanent },
                    { name: "Time-Bound", value: pieData.time_bound },
                  ]}
                  cx="50%"
                  cy="50%"
                  outerRadius={90}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}
                >
                  <Cell fill="#e74c3c" />
                  <Cell fill="#2ecc71" />
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  );
}

/* ── Assignments Tab ─────────────────────────────────────────── */

const assignmentColumns: ColumnDef<PIMAssignment>[] = [
  {
    key: "principal",
    header: "Principal",
    groupable: true,
    value: (a) => a.principal_display_name || a.principal_id,
  },
  {
    key: "principal_type",
    header: "Type",
    groupable: true,
    value: (a) => a.principal_type || "–",
    render: (a) => <span className="badge badge-info">{a.principal_type || "–"}</span>,
  },
  {
    key: "role",
    header: "Role",
    groupable: true,
    value: (a) => a.role_display_name,
  },
  {
    key: "assignment_type",
    header: "Assignment",
    groupable: true,
    value: (a) => a.assignment_type || "–",
    render: (a) => (
      <span className={`badge badge-${a.assignment_type === "Activated" ? "high" : "info"}`}>
        {a.assignment_type || "–"}
      </span>
    ),
  },
  {
    key: "scope",
    header: "Scope",
    value: (a) => a.directory_scope_id,
    render: (a) => (
      <span style={{ fontFamily: "monospace", fontSize: "0.85rem" }}>{a.directory_scope_id}</span>
    ),
  },
  {
    key: "start",
    header: "Start",
    value: (a) => a.start_date_time,
    render: (a) => fmtDate(a.start_date_time),
  },
  {
    key: "end",
    header: "End",
    value: (a) => a.end_date_time,
    render: (a) =>
      a.is_permanent ? (
        <span className="badge badge-critical">Permanent</span>
      ) : (
        fmtDate(a.end_date_time)
      ),
  },
];

function AssignmentsTab() {
  const [offset, setOffset] = useState(0);
  const [roleFilter, setRoleFilter] = useState("");
  const [principalFilter, setPrincipalFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const params: Record<string, string> = {
    offset: String(offset),
    limit: String(PAGE_SIZE),
  };
  if (roleFilter) params.role = roleFilter;
  if (principalFilter) params.principal = principalFilter;
  if (typeFilter) params.assignment_type = typeFilter;

  const { data, isLoading, error } = useQuery<PaginatedResponse<PIMAssignment>>({
    queryKey: ["pim", "assignments", offset, roleFilter, principalFilter, typeFilter],
    queryFn: () => fetchPIMAssignments(params),
  });

  const items = data?.items ?? [];
  const total = data?.total ?? 0;

  return (
    <div>
      <div className="filters">
        <input placeholder="Filter by role…" value={roleFilter} onChange={(e) => { setRoleFilter(e.target.value); setOffset(0); }} />
        <input placeholder="Filter by principal…" value={principalFilter} onChange={(e) => { setPrincipalFilter(e.target.value); setOffset(0); }} />
        <select value={typeFilter} onChange={(e) => { setTypeFilter(e.target.value); setOffset(0); }}>
          <option value="">All Types</option>
          <option value="Assigned">Assigned</option>
          <option value="Activated">Activated</option>
        </select>
      </div>

      {error && <div className="error-box">{String(error)}</div>}

      {isLoading ? (
        <p className="loading">Loading…</p>
      ) : (
        <SortableTable
          columns={assignmentColumns}
          data={items}
          rowKey={(a) => a.id}
          expandedKey={expandedId}
          onToggleExpand={(key) => setExpandedId(expandedId === key ? null : (key as string))}
          renderExpanded={(a) => (
            <div className="user-detail-panel">
              <h4>Raw Assignment JSON</h4>
              <JsonView data={a.raw_json} initialExpanded={false} />
            </div>
          )}
          defaultSort={{ key: "role", dir: "asc" }}
        />
      )}
      <Pagination offset={offset} total={total} pageSize={PAGE_SIZE} onChange={setOffset} />
    </div>
  );
}

/* ── Eligibilities Tab ────────────────────────────────────────── */

const eligibilityColumns: ColumnDef<PIMEligibility>[] = [
  {
    key: "principal",
    header: "Principal",
    groupable: true,
    value: (e) => e.principal_display_name || e.principal_id,
  },
  {
    key: "principal_type",
    header: "Type",
    groupable: true,
    value: (e) => e.principal_type || "–",
    render: (e) => <span className="badge badge-info">{e.principal_type || "–"}</span>,
  },
  {
    key: "role",
    header: "Role",
    groupable: true,
    value: (e) => e.role_display_name,
  },
  {
    key: "scope",
    header: "Scope",
    value: (e) => e.directory_scope_id,
    render: (e) => (
      <span style={{ fontFamily: "monospace", fontSize: "0.85rem" }}>{e.directory_scope_id}</span>
    ),
  },
  {
    key: "start",
    header: "Start",
    value: (e) => e.start_date_time,
    render: (e) => fmtDate(e.start_date_time),
  },
  {
    key: "end",
    header: "End",
    value: (e) => e.end_date_time,
    render: (e) => fmtDate(e.end_date_time),
  },
];

function EligibilitiesTab() {
  const [offset, setOffset] = useState(0);
  const [roleFilter, setRoleFilter] = useState("");
  const [principalFilter, setPrincipalFilter] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const params: Record<string, string> = {
    offset: String(offset),
    limit: String(PAGE_SIZE),
  };
  if (roleFilter) params.role = roleFilter;
  if (principalFilter) params.principal = principalFilter;

  const { data, isLoading, error } = useQuery<PaginatedResponse<PIMEligibility>>({
    queryKey: ["pim", "eligibilities", offset, roleFilter, principalFilter],
    queryFn: () => fetchPIMEligibilities(params),
  });

  const items = data?.items ?? [];
  const total = data?.total ?? 0;

  return (
    <div>
      <div className="filters">
        <input placeholder="Filter by role…" value={roleFilter} onChange={(e) => { setRoleFilter(e.target.value); setOffset(0); }} />
        <input placeholder="Filter by principal…" value={principalFilter} onChange={(e) => { setPrincipalFilter(e.target.value); setOffset(0); }} />
      </div>

      {error && <div className="error-box">{String(error)}</div>}

      {isLoading ? (
        <p className="loading">Loading…</p>
      ) : (
        <SortableTable
          columns={eligibilityColumns}
          data={items}
          rowKey={(e) => e.id}
          expandedKey={expandedId}
          onToggleExpand={(key) => setExpandedId(expandedId === key ? null : (key as string))}
          renderExpanded={(e) => (
            <div className="user-detail-panel">
              <h4>Raw Eligibility JSON</h4>
              <JsonView data={e.raw_json} initialExpanded={false} />
            </div>
          )}
          defaultSort={{ key: "role", dir: "asc" }}
        />
      )}
      <Pagination offset={offset} total={total} pageSize={PAGE_SIZE} onChange={setOffset} />
    </div>
  );
}

/* ── Activations Tab ─────────────────────────────────────────── */

const activationColumns: ColumnDef<PIMActivation>[] = [
  {
    key: "created_date_time",
    header: "Time",
    value: (a) => a.created_date_time,
    render: (a) => fmtDate(a.created_date_time),
  },
  {
    key: "user",
    header: "User",
    groupable: true,
    value: (a) => a.principal_display_name || a.principal_id,
  },
  {
    key: "role",
    header: "Role",
    groupable: true,
    value: (a) => a.role_display_name,
  },
  {
    key: "action",
    header: "Action",
    groupable: true,
    value: (a) => a.action,
    render: (a) => {
      const badge = a.action.toLowerCase().includes("activate")
        ? a.action.toLowerCase().includes("deactivate") ? "medium" : "high"
        : "info";
      return <span className={`badge badge-${badge}`}>{a.action}</span>;
    },
  },
  {
    key: "status",
    header: "Status",
    groupable: true,
    value: (a) => a.status,
    render: (a) => (
      <span className={`badge badge-${a.status === "Provisioned" ? "low" : a.status === "Revoked" ? "medium" : "info"}`}>
        {a.status}
      </span>
    ),
  },
  {
    key: "justification",
    header: "Justification",
    sortable: false,
    value: (a) => a.justification || "",
    render: (a) => (
      <span
        style={{ maxWidth: "300px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "inline-block" }}
        title={a.justification}
      >
        {a.justification || "–"}
      </span>
    ),
  },
];

function ActivationsTab() {
  const [offset, setOffset] = useState(0);
  const [roleFilter, setRoleFilter] = useState("");
  const [principalFilter, setPrincipalFilter] = useState("");
  const [actionFilter, setActionFilter] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const params: Record<string, string> = {
    offset: String(offset),
    limit: String(PAGE_SIZE),
  };
  if (roleFilter) params.role = roleFilter;
  if (principalFilter) params.principal = principalFilter;
  if (actionFilter) params.action = actionFilter;

  const { data, isLoading, error } = useQuery<PaginatedResponse<PIMActivation>>({
    queryKey: ["pim", "activations", offset, roleFilter, principalFilter, actionFilter],
    queryFn: () => fetchPIMActivations(params),
  });

  const items = data?.items ?? [];
  const total = data?.total ?? 0;

  return (
    <div>
      <div className="filters">
        <input placeholder="Filter by role…" value={roleFilter} onChange={(e) => { setRoleFilter(e.target.value); setOffset(0); }} />
        <input placeholder="Filter by user…" value={principalFilter} onChange={(e) => { setPrincipalFilter(e.target.value); setOffset(0); }} />
        <select value={actionFilter} onChange={(e) => { setActionFilter(e.target.value); setOffset(0); }}>
          <option value="">All Actions</option>
          <option value="selfActivate">Self Activate</option>
          <option value="selfDeactivate">Self Deactivate</option>
          <option value="adminAssign">Admin Assign</option>
          <option value="adminRemove">Admin Remove</option>
        </select>
      </div>

      {error && <div className="error-box">{String(error)}</div>}

      {isLoading ? (
        <p className="loading">Loading…</p>
      ) : (
        <SortableTable
          columns={activationColumns}
          data={items}
          rowKey={(a) => a.id}
          expandedKey={expandedId}
          onToggleExpand={(key) => setExpandedId(expandedId === key ? null : (key as string))}
          renderExpanded={(a) => (
            <div className="user-detail-panel">
              <div className="detail-grid">
                <div className="detail-section">
                  <h4>Details</h4>
                  <table className="nested-table">
                    <tbody>
                      <tr><td><strong>Action</strong></td><td>{a.action}</td></tr>
                      <tr><td><strong>Status</strong></td><td>{a.status}</td></tr>
                      <tr><td><strong>Role</strong></td><td>{a.role_display_name}</td></tr>
                      <tr><td><strong>Principal</strong></td><td>{a.principal_display_name || a.principal_id}</td></tr>
                      <tr><td><strong>Created</strong></td><td>{fmtDate(a.created_date_time)}</td></tr>
                      <tr><td><strong>Schedule Start</strong></td><td>{fmtDate(a.schedule_start)}</td></tr>
                      <tr><td><strong>Schedule End</strong></td><td>{fmtDate(a.schedule_end)}</td></tr>
                      {a.justification && <tr><td><strong>Justification</strong></td><td style={{ whiteSpace: "pre-wrap" }}>{a.justification}</td></tr>}
                    </tbody>
                  </table>
                </div>
                <div className="detail-section">
                  <h4>Raw JSON</h4>
                  <JsonView data={a.raw_json} initialExpanded={false} />
                </div>
              </div>
            </div>
          )}
          defaultSort={{ key: "created_date_time", dir: "desc" }}
        />
      )}
      <Pagination offset={offset} total={total} pageSize={PAGE_SIZE} onChange={setOffset} />
    </div>
  );
}

/* ── Audit Logs Tab ──────────────────────────────────────────── */

const auditColumns: ColumnDef<PIMAuditLog>[] = [
  {
    key: "activity_date_time",
    header: "Time",
    value: (a) => a.activity_date_time,
    render: (a) => fmtDate(a.activity_date_time),
  },
  {
    key: "activity",
    header: "Activity",
    groupable: true,
    value: (a) => a.activity_display_name,
  },
  {
    key: "initiated_by",
    header: "Initiated By",
    groupable: true,
    value: (a) => a.initiated_by_user_display_name || a.initiated_by_user_upn || a.initiated_by_app_display_name || "–",
  },
  {
    key: "result",
    header: "Result",
    groupable: true,
    value: (a) => a.result || "–",
    render: (a) => (
      <span className={`badge badge-${a.result === "success" ? "low" : a.result === "failure" ? "critical" : "info"}`}>
        {a.result || "–"}
      </span>
    ),
  },
];

function AuditLogsTab() {
  const [offset, setOffset] = useState(0);
  const [activityFilter, setActivityFilter] = useState("");
  const [userFilter, setUserFilter] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const params: Record<string, string> = {
    offset: String(offset),
    limit: String(PAGE_SIZE),
  };
  if (activityFilter) params.activity = activityFilter;
  if (userFilter) params.user = userFilter;

  const { data, isLoading, error } = useQuery<PaginatedResponse<PIMAuditLog>>({
    queryKey: ["pim", "audit-logs", offset, activityFilter, userFilter],
    queryFn: () => fetchPIMAuditLogs(params),
  });

  const items = data?.items ?? [];
  const total = data?.total ?? 0;

  return (
    <div>
      <div className="filters">
        <input placeholder="Filter by activity…" value={activityFilter} onChange={(e) => { setActivityFilter(e.target.value); setOffset(0); }} />
        <input placeholder="Filter by user…" value={userFilter} onChange={(e) => { setUserFilter(e.target.value); setOffset(0); }} />
      </div>

      {error && <div className="error-box">{String(error)}</div>}

      {isLoading ? (
        <p className="loading">Loading…</p>
      ) : (
        <SortableTable
          columns={auditColumns}
          data={items}
          rowKey={(a) => a.id}
          expandedKey={expandedId}
          onToggleExpand={(key) => setExpandedId(expandedId === key ? null : (key as string))}
          renderExpanded={(a) => (
            <div className="user-detail-panel">
              <div className="detail-grid">
                <div className="detail-section">
                  <h4>Details</h4>
                  <table className="nested-table">
                    <tbody>
                      <tr><td><strong>Activity</strong></td><td>{a.activity_display_name}</td></tr>
                      <tr><td><strong>Result</strong></td><td>{a.result}</td></tr>
                      {a.result_reason && <tr><td><strong>Reason</strong></td><td>{a.result_reason}</td></tr>}
                      <tr><td><strong>Initiated By (User)</strong></td><td>{a.initiated_by_user_display_name || a.initiated_by_user_upn || "–"}</td></tr>
                      {a.initiated_by_app_display_name && <tr><td><strong>Initiated By (App)</strong></td><td>{a.initiated_by_app_display_name}</td></tr>}
                    </tbody>
                  </table>
                </div>
                {a.target_resources && a.target_resources.length > 0 && (
                  <div className="detail-section">
                    <h4>Target Resources</h4>
                    <JsonView data={a.target_resources} initialExpanded={false} />
                  </div>
                )}
                <div className="detail-section" style={{ gridColumn: "1 / -1" }}>
                  <h4>Raw Audit JSON</h4>
                  <JsonView data={a.raw_json} initialExpanded={false} />
                </div>
              </div>
            </div>
          )}
          defaultSort={{ key: "activity_date_time", dir: "desc" }}
        />
      )}
      <Pagination offset={offset} total={total} pageSize={PAGE_SIZE} onChange={setOffset} />
    </div>
  );
}

/* ── Insights Tab ────────────────────────────────────────────── */

interface RoleDist {
  role: string;
  active: number;
  eligible: number;
}

const roleDistColumns: ColumnDef<RoleDist>[] = [
  { key: "role", header: "Role", value: (r) => r.role },
  { key: "active", header: "Active Assignments", value: (r) => r.active },
  { key: "eligible", header: "Eligible Assignments", value: (r) => r.eligible },
  {
    key: "total",
    header: "Total",
    value: (r) => r.active + r.eligible,
    render: (r) => <strong>{r.active + r.eligible}</strong>,
  },
];

function InsightsTab() {
  const { data, isLoading } = useQuery<PIMInsights>({
    queryKey: ["pim", "insights"],
    queryFn: fetchPIMInsights,
  });

  if (isLoading) return <p className="loading">Loading…</p>;
  if (!data) return <p style={{ color: "var(--text-secondary)" }}>No data — sync PIM data first.</p>;

  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem" }}>
        <div className="card">
          <h3>Top Activated Roles</h3>
          {data.top_activated_roles.length === 0 ? (
            <p style={{ color: "var(--text-secondary)" }}>No activations recorded.</p>
          ) : (
            <ResponsiveContainer width="100%" height={Math.max(200, data.top_activated_roles.length * 32)}>
              <BarChart data={data.top_activated_roles} layout="vertical" margin={{ left: 160 }}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" />
                <YAxis dataKey="role" type="category" tick={{ fontSize: 12 }} width={150} />
                <Tooltip />
                <Bar dataKey="count" fill="#5b8dfa" name="Activations" />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="card">
          <h3>Top Activating Users</h3>
          {data.top_activating_users.length === 0 ? (
            <p style={{ color: "var(--text-secondary)" }}>No activations recorded.</p>
          ) : (
            <ResponsiveContainer width="100%" height={Math.max(200, data.top_activating_users.length * 32)}>
              <BarChart data={data.top_activating_users} layout="vertical" margin={{ left: 160 }}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" />
                <YAxis dataKey="user" type="category" tick={{ fontSize: 12 }} width={150} />
                <Tooltip />
                <Bar dataKey="count" fill="#f5a623" name="Activations" />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div className="card" style={{ marginTop: "1.5rem" }}>
        <h3>Role Assignment Breakdown</h3>
        {data.role_distribution.length === 0 ? (
          <p style={{ color: "var(--text-secondary)" }}>No role data.</p>
        ) : (
          <SortableTable
            columns={roleDistColumns}
            data={data.role_distribution}
            rowKey={(r) => r.role}
            defaultSort={{ key: "total", dir: "desc" }}
            showGroupBy={false}
          />
        )}
      </div>

      {data.permanent_vs_timebound.permanent > 0 && (
        <div className="risk-alert" style={{ marginTop: "1.5rem" }}>
          <strong>Warning:</strong> There are <strong>{data.permanent_vs_timebound.permanent}</strong> permanent role assignments.
          Consider converting these to time-bound eligible assignments for better security posture.
        </div>
      )}
    </div>
  );
}

/* ── Shared Components ───────────────────────────────────────── */

function KPI({ label, value, warn }: { label: string; value?: number; warn?: boolean }) {
  return (
    <div className="kpi-card">
      <div className="kpi-value" style={warn ? { color: "var(--danger)" } : undefined}>
        {value ?? "–"}
      </div>
      <div className="kpi-label">{label}</div>
    </div>
  );
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
