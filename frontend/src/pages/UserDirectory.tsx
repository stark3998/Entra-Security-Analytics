import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  fetchDirectoryUsers,
  fetchDirectoryUserStats,
  syncDirectoryUsers,
  type EntraUser,
  type DirectoryUserStats,
  type PaginatedResponse,
} from "../api";
import SortableTable, { type ColumnDef } from "../components/SortableTable";
import JsonView from "../components/JsonView";

const PAGE_SIZE = 50;

function fmtDate(iso: string | null): string {
  if (!iso) return "–";
  return new Date(iso).toLocaleString();
}

const columns: ColumnDef<EntraUser>[] = [
  {
    key: "display_name",
    header: "Display Name",
    filterable: true,
    value: (u) => u.display_name || u.user_principal_name,
    render: (u) => (
      <div>
        <div style={{ fontWeight: 600 }}>{u.display_name || u.user_principal_name}</div>
        <div style={{ color: "var(--text-secondary)", fontSize: "0.78rem" }}>
          {u.user_principal_name}
        </div>
      </div>
    ),
  },
  {
    key: "mail",
    header: "Email",
    filterable: true,
    value: (u) => u.mail,
  },
  {
    key: "department",
    header: "Department",
    groupable: true,
    filterable: true,
    value: (u) => u.department || "–",
  },
  {
    key: "job_title",
    header: "Job Title",
    filterable: true,
    value: (u) => u.job_title || "–",
  },
  {
    key: "user_type",
    header: "Type",
    groupable: true,
    value: (u) => u.user_type || "–",
    render: (u) =>
      u.user_type === "Guest" ? (
        <span className="badge badge-medium">Guest</span>
      ) : (
        <span className="badge badge-info">{u.user_type || "–"}</span>
      ),
  },
  {
    key: "account_enabled",
    header: "Enabled",
    groupable: true,
    value: (u) => (u.account_enabled ? "Yes" : "No"),
    render: (u) =>
      u.account_enabled ? (
        <span className="badge badge-info">Enabled</span>
      ) : (
        <span className="badge badge-critical">Disabled</span>
      ),
  },
  {
    key: "last_sign_in",
    header: "Last Sign-In",
    value: (u) => u.last_sign_in_date_time,
    render: (u) => fmtDate(u.last_sign_in_date_time),
  },
  {
    key: "created",
    header: "Created",
    value: (u) => u.created_date_time,
    render: (u) => fmtDate(u.created_date_time),
  },
];

export default function UserDirectory() {
  const [offset, setOffset] = useState(0);
  const [search, setSearch] = useState("");
  const [userTypeFilter, setUserTypeFilter] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const queryClient = useQueryClient();

  const params: Record<string, string> = {
    offset: String(offset),
    limit: String(PAGE_SIZE),
  };
  if (search) params.search = search;
  if (userTypeFilter) params.user_type = userTypeFilter;

  const { data, isLoading, error } = useQuery<PaginatedResponse<EntraUser>>({
    queryKey: ["directory-users", offset, search, userTypeFilter],
    queryFn: () => fetchDirectoryUsers(params),
  });

  const { data: stats } = useQuery<DirectoryUserStats>({
    queryKey: ["directory-users-stats"],
    queryFn: fetchDirectoryUserStats,
  });

  const total = data?.total ?? 0;
  const items = data?.items ?? [];

  const handleSync = async () => {
    setSyncing(true);
    try {
      await syncDirectoryUsers();
      queryClient.invalidateQueries({ queryKey: ["directory-users"] });
      queryClient.invalidateQueries({ queryKey: ["directory-users-stats"] });
    } finally {
      setSyncing(false);
    }
  };

  return (
    <div>
      <div className="page-header-row">
        <div>
          <h1 className="page-heading">User Directory</h1>
          <p className="page-subtitle">
            Entra ID user profiles synced from Microsoft Graph — click a user to see full details and raw JSON
          </p>
        </div>
        <button
          className="btn btn-primary btn-sm"
          onClick={handleSync}
          disabled={syncing}
        >
          {syncing ? "Syncing…" : "Sync Users"}
        </button>
      </div>

      {/* KPI strip */}
      {stats && (
        <div className="kpi-strip">
          <div className="kpi-card">
            <div className="kpi-value">{stats.total}</div>
            <div className="kpi-label">Total Users</div>
          </div>
          <div className="kpi-card">
            <div className="kpi-value">{stats.total - stats.guests}</div>
            <div className="kpi-label">Members</div>
          </div>
          <div className="kpi-card">
            <div className="kpi-value">{stats.guests}</div>
            <div className="kpi-label">Guests</div>
          </div>
          <div className="kpi-card">
            <div className="kpi-value">{stats.disabled}</div>
            <div className="kpi-label">Disabled</div>
          </div>
          <div className="kpi-card">
            <div className="kpi-value">{stats.licensed}</div>
            <div className="kpi-label">Licensed</div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="filters">
        <input
          placeholder="Search by name, UPN, department, email…"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setOffset(0);
          }}
        />
        <select
          value={userTypeFilter}
          onChange={(e) => {
            setUserTypeFilter(e.target.value);
            setOffset(0);
          }}
        >
          <option value="">All Types</option>
          <option value="Member">Member</option>
          <option value="Guest">Guest</option>
        </select>
      </div>

      {error && <div className="error-box">{String(error)}</div>}

      <div className="card">
        {isLoading ? (
          <p className="loading">Loading…</p>
        ) : items.length === 0 ? (
          <p className="loading">
            No users found. Click "Sync Users" to fetch from Microsoft Graph.
          </p>
        ) : (
          <SortableTable
            columns={columns}
            data={items}
            rowKey={(u) => u.id}
            expandedKey={expandedId}
            onToggleExpand={(key) =>
              setExpandedId(expandedId === key ? null : (key as string))
            }
            renderExpanded={(u) => <UserDetails user={u} />}
            defaultSort={{ key: "display_name", dir: "asc" }}
          />
        )}

        <Pagination
          offset={offset}
          total={total}
          pageSize={PAGE_SIZE}
          onChange={setOffset}
        />
      </div>
    </div>
  );
}

/* ── Expanded user details panel ───────────────────────── */

function UserDetails({ user: u }: { user: EntraUser }) {
  return (
    <div className="user-detail-panel">
      <div className="detail-grid">
        <div className="detail-section">
          <h4>Identity</h4>
          <table className="nested-table">
            <tbody>
              <tr>
                <td><strong>Object ID</strong></td>
                <td style={{ fontFamily: "monospace", fontSize: "0.82rem" }}>{u.id}</td>
              </tr>
              <tr>
                <td><strong>UPN</strong></td>
                <td>{u.user_principal_name}</td>
              </tr>
              <tr>
                <td><strong>Display Name</strong></td>
                <td>{u.display_name || "–"}</td>
              </tr>
              <tr>
                <td><strong>Email</strong></td>
                <td>{u.mail || "–"}</td>
              </tr>
              <tr>
                <td><strong>User Type</strong></td>
                <td>
                  {u.user_type === "Guest" ? (
                    <span className="badge badge-medium">Guest</span>
                  ) : (
                    <span className="badge badge-info">{u.user_type || "–"}</span>
                  )}
                </td>
              </tr>
              <tr>
                <td><strong>Account Enabled</strong></td>
                <td>
                  {u.account_enabled ? (
                    <span className="badge badge-info">Yes</span>
                  ) : (
                    <span className="badge badge-critical">No</span>
                  )}
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div className="detail-section">
          <h4>Organization</h4>
          <table className="nested-table">
            <tbody>
              <tr>
                <td><strong>Job Title</strong></td>
                <td>{u.job_title || "–"}</td>
              </tr>
              <tr>
                <td><strong>Department</strong></td>
                <td>{u.department || "–"}</td>
              </tr>
              <tr>
                <td><strong>Company</strong></td>
                <td>{u.company_name || "–"}</td>
              </tr>
              <tr>
                <td><strong>Office Location</strong></td>
                <td>{u.office_location || "–"}</td>
              </tr>
              <tr>
                <td><strong>Mobile Phone</strong></td>
                <td>{u.mobile_phone || "–"}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div className="detail-section">
          <h4>Activity</h4>
          <table className="nested-table">
            <tbody>
              <tr>
                <td><strong>Created</strong></td>
                <td>{fmtDate(u.created_date_time)}</td>
              </tr>
              <tr>
                <td><strong>Last Sign-In</strong></td>
                <td>{fmtDate(u.last_sign_in_date_time)}</td>
              </tr>
              <tr>
                <td><strong>Last Synced</strong></td>
                <td>{fmtDate(u.synced_at)}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div className="detail-section">
          <h4>Licenses ({u.assigned_licenses.length})</h4>
          {u.assigned_licenses.length > 0 ? (
            <ul style={{ margin: 0, paddingLeft: "1.2rem", fontSize: "0.82rem" }}>
              {u.assigned_licenses.map((lic: any, i: number) => (
                <li key={i} style={{ fontFamily: "monospace" }}>
                  {lic.skuId || JSON.stringify(lic)}
                </li>
              ))}
            </ul>
          ) : (
            <p style={{ color: "var(--text-secondary)", fontSize: "0.82rem" }}>
              No licenses assigned
            </p>
          )}
        </div>

        <div className="detail-section" style={{ gridColumn: "1 / -1" }}>
          <h4>Raw Graph API Response</h4>
          <JsonView data={u.raw_json} initialExpanded={false} />
        </div>
      </div>
    </div>
  );
}

/* ── Helpers ────────────────────────────────────────────── */

function Pagination({
  offset,
  total,
  pageSize,
  onChange,
}: {
  offset: number;
  total: number;
  pageSize: number;
  onChange: (o: number) => void;
}) {
  const page = Math.floor(offset / pageSize) + 1;
  const pages = Math.ceil(total / pageSize) || 1;
  return (
    <div className="pagination">
      <button disabled={offset === 0} onClick={() => onChange(offset - pageSize)}>
        ← Prev
      </button>
      <span>
        Page {page} of {pages} ({total} total)
      </span>
      <button
        disabled={offset + pageSize >= total}
        onClick={() => onChange(offset + pageSize)}
      >
        Next →
      </button>
    </div>
  );
}
