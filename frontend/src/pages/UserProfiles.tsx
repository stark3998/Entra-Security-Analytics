import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  fetchUserProfiles,
  fetchUserProfile,
  refreshUserProfiles,
  type UserProfile,
  type UserProfileDetail,
  type PaginatedResponse,
} from "../api";

const PAGE_SIZE = 30;

export default function UserProfiles() {
  const [offset, setOffset] = useState(0);
  const [search, setSearch] = useState("");
  const [riskyOnly, setRiskyOnly] = useState(false);
  const [expandedUser, setExpandedUser] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const queryClient = useQueryClient();

  const params: Record<string, string> = {
    offset: String(offset),
    limit: String(PAGE_SIZE),
  };
  if (search) params.search = search;
  if (riskyOnly) params.risky_only = "true";

  const { data, isLoading, error } = useQuery<PaginatedResponse<UserProfile>>({
    queryKey: ["user-profiles", offset, search, riskyOnly],
    queryFn: () => fetchUserProfiles(params),
  });

  const total = data?.total ?? 0;
  const items = data?.items ?? [];

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await refreshUserProfiles();
      queryClient.invalidateQueries({ queryKey: ["user-profiles"] });
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <div>
      <div className="page-header-row">
        <h1 className="page-heading">User Sign-In Profiles</h1>
        <button
          className="btn btn-primary btn-sm"
          onClick={handleRefresh}
          disabled={refreshing}
        >
          {refreshing ? "Refreshing…" : "Refresh Profiles"}
        </button>
      </div>

      <div className="filters">
        <input
          placeholder="Search by user…"
          value={search}
          onChange={(e) => { setSearch(e.target.value); setOffset(0); }}
        />
        <label className="filter-checkbox">
          <input
            type="checkbox"
            checked={riskyOnly}
            onChange={(e) => { setRiskyOnly(e.target.checked); setOffset(0); }}
          />
          Risky users only
        </label>
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
                  <th></th>
                  <th>User</th>
                  <th>Sign-Ins</th>
                  <th>Locations</th>
                  <th>Devices</th>
                  <th>IPs</th>
                  <th>First Seen</th>
                  <th>Last Seen</th>
                  <th>Risk</th>
                </tr>
              </thead>
              <tbody>
                {items.map((p) => (
                  <UserRow
                    key={p.user_principal_name}
                    profile={p}
                    isExpanded={expandedUser === p.user_principal_name}
                    onToggle={() =>
                      setExpandedUser(
                        expandedUser === p.user_principal_name ? null : p.user_principal_name
                      )
                    }
                  />
                ))}
                {items.length === 0 && (
                  <tr><td colSpan={9} className="loading">No user profiles found. Run a sync to build profiles.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        <Pagination offset={offset} total={total} pageSize={PAGE_SIZE} onChange={setOffset} />
      </div>
    </div>
  );
}

/* ── User Row (expandable) ──────────────────────────────── */

function UserRow({
  profile: p,
  isExpanded,
  onToggle,
}: {
  profile: UserProfile;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  return (
    <>
      <tr className="clickable-row" onClick={onToggle}>
        <td className="expand-arrow">{isExpanded ? "▼" : "▶"}</td>
        <td>
          <div className="user-cell">
            <span className="user-name">{p.user_display_name || p.user_principal_name}</span>
            <span className="user-upn">{p.user_principal_name}</span>
          </div>
        </td>
        <td>{p.total_sign_ins}</td>
        <td>{p.known_locations.length}</td>
        <td>{p.known_devices.length}</td>
        <td>{p.known_ips.length}</td>
        <td>{fmtDate(p.first_seen)}</td>
        <td>{fmtDate(p.last_seen)}</td>
        <td>
          {p.is_risky ? (
            <span className="badge badge-critical">RISKY</span>
          ) : (
            <span className="badge badge-info">Normal</span>
          )}
        </td>
      </tr>
      {isExpanded && (
        <tr className="expanded-row">
          <td colSpan={9}>
            <UserDetails upn={p.user_principal_name} profile={p} />
          </td>
        </tr>
      )}
    </>
  );
}

/* ── Expanded details panel ─────────────────────────────── */

function UserDetails({ upn, profile }: { upn: string; profile: UserProfile }) {
  const { data, isLoading } = useQuery<UserProfileDetail>({
    queryKey: ["user-profile-detail", upn],
    queryFn: () => fetchUserProfile(upn),
  });

  return (
    <div className="user-detail-panel">
      {/* Risk reasons */}
      {profile.is_risky && profile.risk_reasons.length > 0 && (
        <div className="risk-alert">
          <strong>Risk Reasons:</strong>
          <ul>
            {profile.risk_reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="detail-grid">
        {/* Known Locations */}
        <div className="detail-section">
          <h4>Known Locations ({profile.known_locations.length})</h4>
          <div className="table-wrapper">
            <table className="nested-table">
              <thead>
                <tr>
                  <th>City</th>
                  <th>State</th>
                  <th>Country</th>
                  <th>Count</th>
                  <th>First Seen</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {profile.known_locations.map((loc, i) => (
                  <tr key={i}>
                    <td>{loc.city || "–"}</td>
                    <td>{loc.state || "–"}</td>
                    <td>{loc.country || "–"}</td>
                    <td>{loc.count}</td>
                    <td>{fmtDate(loc.first_seen)}</td>
                    <td>{fmtDate(loc.last_seen)}</td>
                  </tr>
                ))}
                {profile.known_locations.length === 0 && (
                  <tr><td colSpan={6} className="loading">No locations recorded</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Known Devices */}
        <div className="detail-section">
          <h4>Known Devices ({profile.known_devices.length})</h4>
          <div className="table-wrapper">
            <table className="nested-table">
              <thead>
                <tr>
                  <th>OS</th>
                  <th>Browser</th>
                  <th>Count</th>
                  <th>First Seen</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {profile.known_devices.map((dev, i) => (
                  <tr key={i}>
                    <td>{dev.device_os || "–"}</td>
                    <td>{dev.device_browser || "–"}</td>
                    <td>{dev.count}</td>
                    <td>{fmtDate(dev.first_seen)}</td>
                    <td>{fmtDate(dev.last_seen)}</td>
                  </tr>
                ))}
                {profile.known_devices.length === 0 && (
                  <tr><td colSpan={5} className="loading">No devices recorded</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Known IPs */}
        <div className="detail-section">
          <h4>Known IPs ({profile.known_ips.length})</h4>
          <div className="table-wrapper">
            <table className="nested-table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Count</th>
                  <th>First Seen</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {profile.known_ips.map((ip, i) => (
                  <tr key={i}>
                    <td>{ip.ip_address}</td>
                    <td>{ip.count}</td>
                    <td>{fmtDate(ip.first_seen)}</td>
                    <td>{fmtDate(ip.last_seen)}</td>
                  </tr>
                ))}
                {profile.known_ips.length === 0 && (
                  <tr><td colSpan={4} className="loading">No IPs recorded</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Sign-In Hour Histogram */}
        <div className="detail-section">
          <h4>Sign-In Time Pattern (UTC)</h4>
          <div className="hour-histogram">
            {profile.sign_in_hour_histogram.map((count, hour) => {
              const maxCount = Math.max(...profile.sign_in_hour_histogram, 1);
              const heightPct = (count / maxCount) * 100;
              return (
                <div key={hour} className="hour-bar-wrapper" title={`${hour}:00 — ${count} sign-ins`}>
                  <div className="hour-bar" style={{ height: `${heightPct}%` }} />
                  <span className="hour-label">{hour}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Recent Sign-In Logs */}
      <div className="detail-section" style={{ marginTop: "1rem" }}>
        <h4>Recent Sign-In Logs</h4>
        {isLoading ? (
          <p className="loading">Loading logs…</p>
        ) : (
          <div className="table-wrapper">
            <table className="nested-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>App</th>
                  <th>IP</th>
                  <th>Location</th>
                  <th>Device</th>
                  <th>Risk</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {(data?.recent_signin_logs ?? []).map((log) => (
                  <tr key={log.id}>
                    <td>{fmtDate(log.created_datetime)}</td>
                    <td>{log.app_display_name}</td>
                    <td>{log.ip_address}</td>
                    <td>{[log.location_city, log.location_country].filter(Boolean).join(", ")}</td>
                    <td>{[log.device_os, log.device_browser].filter(Boolean).join(" / ")}</td>
                    <td><RiskBadge level={log.risk_level} /></td>
                    <td>{log.status_error_code === 0 ? "✓" : `✗ ${log.status_error_code}`}</td>
                  </tr>
                ))}
                {(data?.recent_signin_logs ?? []).length === 0 && (
                  <tr><td colSpan={7} className="loading">No recent logs</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

/* ── Helpers ────────────────────────────────────────────── */

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
