import { useState, useEffect, useRef } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  fetchUserProfiles,
  fetchUserProfile,
  refreshUserProfiles,
  type UserProfile,
  type UserProfileDetail,
  type KnownLocation,
  type AuditLogSummary,
  type ActivityLogSummary,
  type PaginatedResponse,
} from "../api";
import SortableTable, { type ColumnDef } from "../components/SortableTable";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

const PAGE_SIZE = 30;

const columns: ColumnDef<UserProfile>[] = [
  {
    key: "user",
    header: "User",
    value: (p) => p.user_display_name || p.user_principal_name,
    render: (p) => (
      <div className="user-cell">
        <span className="user-name">{p.user_display_name || p.user_principal_name}</span>
        <span className="user-upn">{p.user_principal_name}</span>
      </div>
    ),
  },
  {
    key: "total_sign_ins",
    header: "Sign-Ins",
    value: (p) => p.total_sign_ins,
  },
  {
    key: "locations",
    header: "Locations",
    value: (p) => p.known_locations.length,
  },
  {
    key: "devices",
    header: "Devices",
    value: (p) => p.known_devices.length,
  },
  {
    key: "ips",
    header: "IPs",
    value: (p) => p.known_ips.length,
  },
  {
    key: "first_seen",
    header: "First Seen",
    value: (p) => p.first_seen,
    render: (p) => fmtDate(p.first_seen),
  },
  {
    key: "last_seen",
    header: "Last Seen",
    value: (p) => p.last_seen,
    render: (p) => fmtDate(p.last_seen),
  },
  {
    key: "risk",
    header: "Risk",
    groupable: true,
    value: (p) => (p.is_risky ? "Risky" : "Normal"),
    render: (p) =>
      p.is_risky ? (
        <span className="badge badge-critical">RISKY</span>
      ) : (
        <span className="badge badge-info">Normal</span>
      ),
  },
];

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
        <h1 className="page-heading">User Risk Profiles</h1>
        <p className="page-subtitle">Per-user risk scoring, sign-in patterns, and behavioral anomaly detection</p>
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

      {!isLoading && items.length > 0 && <AllUsersMap profiles={items} />}

      <div className="card">
        {isLoading ? (
          <p className="loading">Loading…</p>
        ) : items.length === 0 ? (
          <p className="loading">No user profiles found. Run a sync to build profiles.</p>
        ) : (
          <SortableTable
            columns={columns}
            data={items}
            rowKey={(p) => p.user_principal_name}
            expandedKey={expandedUser}
            onToggleExpand={(key) => setExpandedUser(expandedUser === key ? null : (key as string))}
            renderExpanded={(p) => <UserDetails upn={p.user_principal_name} profile={p} />}
            defaultSort={{ key: "last_seen", dir: "desc" }}
          />
        )}

        <Pagination offset={offset} total={total} pageSize={PAGE_SIZE} onChange={setOffset} />
      </div>
    </div>
  );
}

/* ── Expanded details panel ─────────────────────────────── */

type DetailTab = "profile" | "signin" | "audit" | "activity";

function UserDetails({ upn, profile }: { upn: string; profile: UserProfile }) {
  const [tab, setTab] = useState<DetailTab>("profile");
  const { data, isLoading } = useQuery<UserProfileDetail>({
    queryKey: ["user-profile-detail", upn],
    queryFn: () => fetchUserProfile(upn),
  });

  const signinCount = data?.recent_signin_logs?.length ?? 0;
  const auditCount = data?.recent_audit_logs?.length ?? 0;
  const activityCount = data?.recent_activity_logs?.length ?? 0;

  return (
    <div className="user-detail-panel">
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

      <div className="tab-bar" style={{ display: "flex", gap: "0", borderBottom: "2px solid var(--border-color, #333)", marginBottom: "1rem" }}>
        {([
          { id: "profile" as DetailTab, label: "Profile" },
          { id: "signin" as DetailTab, label: `Sign-In Logs (${signinCount})` },
          { id: "audit" as DetailTab, label: `Audit Logs (${auditCount})` },
          { id: "activity" as DetailTab, label: `Activity Logs (${activityCount})` },
        ]).map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              padding: "0.5rem 1rem",
              background: tab === t.id ? "var(--bg-active, #1a1a2e)" : "transparent",
              color: tab === t.id ? "var(--accent, #4fc3f7)" : "inherit",
              border: "none",
              borderBottom: tab === t.id ? "2px solid var(--accent, #4fc3f7)" : "2px solid transparent",
              cursor: "pointer",
              fontWeight: tab === t.id ? 600 : 400,
              marginBottom: "-2px",
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "profile" && <ProfileTab profile={profile} />}
      {tab === "signin" && <SignInLogsTab logs={data?.recent_signin_logs ?? []} isLoading={isLoading} />}
      {tab === "audit" && <AuditLogsTab logs={data?.recent_audit_logs ?? []} isLoading={isLoading} />}
      {tab === "activity" && <ActivityLogsTab logs={data?.recent_activity_logs ?? []} isLoading={isLoading} />}
    </div>
  );
}

/* ── All-Users Location Map ────────────────────────────── */

interface UserLocationPoint {
  lat: number;
  lon: number;
  city: string;
  state: string;
  country: string;
  count: number;
  users: { upn: string; displayName: string; isRisky: boolean; count: number }[];
}

function AllUsersMap({ profiles }: { profiles: UserProfile[] }) {
  const mapRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);

  // Aggregate locations across all users, grouping by lat/lon
  const pointMap = new Map<string, UserLocationPoint>();
  profiles.forEach((p) => {
    p.known_locations.forEach((loc) => {
      if (loc.lat == null || loc.lon == null) return;
      const key = `${loc.lat.toFixed(4)},${loc.lon.toFixed(4)}`;
      if (!pointMap.has(key)) {
        pointMap.set(key, {
          lat: loc.lat, lon: loc.lon,
          city: loc.city, state: loc.state, country: loc.country,
          count: 0, users: [],
        });
      }
      const pt = pointMap.get(key)!;
      pt.count += loc.count;
      pt.users.push({
        upn: p.user_principal_name,
        displayName: p.user_display_name || p.user_principal_name,
        isRisky: p.is_risky,
        count: loc.count,
      });
    });
  });
  const points = Array.from(pointMap.values());

  useEffect(() => {
    if (!mapRef.current || points.length === 0) return;

    if (mapInstanceRef.current) {
      mapInstanceRef.current.remove();
      mapInstanceRef.current = null;
    }

    const map = L.map(mapRef.current, { scrollWheelZoom: true });
    mapInstanceRef.current = map;

    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
      maxZoom: 18,
    }).addTo(map);

    const bounds: L.LatLngExpression[] = [];

    points.forEach((pt) => {
      const latLng: L.LatLngExpression = [pt.lat, pt.lon];
      bounds.push(latLng);

      const hasRisky = pt.users.some((u) => u.isRisky);
      const radius = Math.min(Math.max(Math.sqrt(pt.count) * 3, 7), 35);

      const userLines = pt.users
        .sort((a, b) => b.count - a.count)
        .slice(0, 10)
        .map((u) => {
          const badge = u.isRisky ? ' <span style="color:#e74c3c;font-weight:600">RISKY</span>' : "";
          return `${u.displayName} (${u.count})${badge}`;
        });
      const overflow = pt.users.length > 10 ? `<br/><em>…and ${pt.users.length - 10} more</em>` : "";
      const label = [pt.city, pt.state, pt.country].filter(Boolean).join(", ");

      L.circleMarker(latLng, {
        radius,
        fillColor: hasRisky ? "#e74c3c" : "#4fc3f7",
        fillOpacity: 0.7,
        color: hasRisky ? "#c0392b" : "#0288d1",
        weight: 2,
      })
        .bindPopup(
          `<strong>${label}</strong><br/>` +
          `Total sign-ins: ${pt.count}<br/>` +
          `Users: ${pt.users.length}<br/><hr style="margin:4px 0"/>` +
          userLines.join("<br/>") + overflow
        )
        .addTo(map);
    });

    if (bounds.length === 1) {
      map.setView(bounds[0], 4);
    } else {
      map.fitBounds(L.latLngBounds(bounds), { padding: [40, 40] });
    }

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, [profiles.map((p) => p.user_principal_name).join(","), points.length]);

  if (points.length === 0) return null;

  return (
    <div className="card" style={{ marginBottom: "1rem" }}>
      <h3 style={{ margin: "0 0 0.5rem 0" }}>All Users — Sign-In Locations</h3>
      <p style={{ margin: "0 0 0.75rem 0", fontSize: "0.85rem", color: "var(--text-secondary, #888)" }}>
        <span style={{ display: "inline-block", width: 10, height: 10, borderRadius: "50%", backgroundColor: "#4fc3f7", marginRight: 4 }} />
        Normal
        <span style={{ display: "inline-block", width: 10, height: 10, borderRadius: "50%", backgroundColor: "#e74c3c", marginLeft: 12, marginRight: 4 }} />
        Risky user present
      </p>
      <div
        ref={mapRef}
        style={{ height: "400px", width: "100%", borderRadius: "8px", border: "1px solid var(--border-color, #333)" }}
      />
    </div>
  );
}

/* ── Single-User Location Map ─────────────────────────── */

function LocationMap({ locations }: { locations: KnownLocation[] }) {
  const mapRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);

  const geoLocations = locations.filter((loc) => loc.lat != null && loc.lon != null);

  useEffect(() => {
    if (!mapRef.current || geoLocations.length === 0) return;

    // Clean up previous map instance
    if (mapInstanceRef.current) {
      mapInstanceRef.current.remove();
      mapInstanceRef.current = null;
    }

    const map = L.map(mapRef.current, { scrollWheelZoom: true });
    mapInstanceRef.current = map;

    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
      maxZoom: 18,
    }).addTo(map);

    const bounds: L.LatLngExpression[] = [];

    geoLocations.forEach((loc) => {
      const latLng: L.LatLngExpression = [loc.lat!, loc.lon!];
      bounds.push(latLng);

      const label = [loc.city, loc.state, loc.country].filter(Boolean).join(", ");
      const radius = Math.min(Math.max(loc.count * 2, 6), 30);

      L.circleMarker(latLng, {
        radius,
        fillColor: "#4fc3f7",
        fillOpacity: 0.7,
        color: "#0288d1",
        weight: 2,
      })
        .bindPopup(
          `<strong>${label}</strong><br/>` +
          `Sign-ins: ${loc.count}<br/>` +
          `First: ${new Date(loc.first_seen).toLocaleDateString()}<br/>` +
          `Last: ${new Date(loc.last_seen).toLocaleDateString()}<br/>` +
          `<small>${loc.lat!.toFixed(4)}, ${loc.lon!.toFixed(4)}</small>`
        )
        .addTo(map);
    });

    if (bounds.length === 1) {
      map.setView(bounds[0], 6);
    } else {
      map.fitBounds(L.latLngBounds(bounds), { padding: [40, 40] });
    }

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, [geoLocations.map((l) => `${l.lat},${l.lon}`).join(";")]);

  if (geoLocations.length === 0) {
    return (
      <div style={{ padding: "1rem", color: "var(--text-secondary, #888)" }}>
        No location coordinates available for map display.
      </div>
    );
  }

  return (
    <div
      ref={mapRef}
      style={{ height: "350px", width: "100%", borderRadius: "8px", border: "1px solid var(--border-color, #333)" }}
    />
  );
}

/* ── Profile tab ───────────────────────────────────────── */

function ProfileTab({ profile }: { profile: UserProfile }) {
  return (
    <div className="detail-grid">
      <div className="detail-section">
        <h4>Location Map</h4>
        <LocationMap locations={profile.known_locations} />
      </div>

      <div className="detail-section">
        <h4>Known Locations ({profile.known_locations.length})</h4>
        <div className="table-wrapper">
          <table className="nested-table">
            <thead>
              <tr><th>City</th><th>State</th><th>Country</th><th>Count</th><th>First Seen</th><th>Last Seen</th></tr>
            </thead>
            <tbody>
              {profile.known_locations.map((loc, i) => (
                <tr key={i}>
                  <td>{loc.city || "–"}</td><td>{loc.state || "–"}</td><td>{loc.country || "–"}</td>
                  <td>{loc.count}</td><td>{fmtDate(loc.first_seen)}</td><td>{fmtDate(loc.last_seen)}</td>
                </tr>
              ))}
              {profile.known_locations.length === 0 && (
                <tr><td colSpan={6} className="loading">No locations recorded</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="detail-section">
        <h4>Known Devices ({profile.known_devices.length})</h4>
        <div className="table-wrapper">
          <table className="nested-table">
            <thead>
              <tr><th>OS</th><th>Browser</th><th>Count</th><th>First Seen</th><th>Last Seen</th></tr>
            </thead>
            <tbody>
              {profile.known_devices.map((dev, i) => (
                <tr key={i}>
                  <td>{dev.device_os || "–"}</td><td>{dev.device_browser || "–"}</td>
                  <td>{dev.count}</td><td>{fmtDate(dev.first_seen)}</td><td>{fmtDate(dev.last_seen)}</td>
                </tr>
              ))}
              {profile.known_devices.length === 0 && (
                <tr><td colSpan={5} className="loading">No devices recorded</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="detail-section">
        <h4>Known IPs ({profile.known_ips.length})</h4>
        <div className="table-wrapper">
          <table className="nested-table">
            <thead>
              <tr><th>IP Address</th><th>Count</th><th>First Seen</th><th>Last Seen</th></tr>
            </thead>
            <tbody>
              {profile.known_ips.map((ip, i) => (
                <tr key={i}>
                  <td>{ip.ip_address}</td><td>{ip.count}</td>
                  <td>{fmtDate(ip.first_seen)}</td><td>{fmtDate(ip.last_seen)}</td>
                </tr>
              ))}
              {profile.known_ips.length === 0 && (
                <tr><td colSpan={4} className="loading">No IPs recorded</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

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
  );
}

/* ── Sign-In Logs tab ──────────────────────────────────── */

const RISKY_ROW_STYLE = { backgroundColor: "rgba(231, 76, 60, 0.15)", borderLeft: "3px solid #e74c3c" };

function isRiskySignIn(log: UserProfileDetail["recent_signin_logs"][0]): boolean {
  return (
    log.risk_level === "high" || log.risk_level === "medium" ||
    log.status_error_code !== 0 ||
    log.conditional_access_status === "failure"
  );
}

function SignInLogsTab({ logs, isLoading }: { logs: UserProfileDetail["recent_signin_logs"]; isLoading: boolean }) {
  if (isLoading) return <p className="loading">Loading logs…</p>;
  return (
    <div className="table-wrapper">
      <table className="nested-table">
        <thead>
          <tr><th>Time</th><th>App</th><th>IP</th><th>Location</th><th>Device</th><th>Risk</th><th>CA Status</th><th>Status</th></tr>
        </thead>
        <tbody>
          {logs.map((log) => (
            <tr key={log.id} style={isRiskySignIn(log) ? RISKY_ROW_STYLE : undefined}>
              <td>{fmtDate(log.created_datetime)}</td>
              <td>{log.app_display_name}</td>
              <td>{log.ip_address}</td>
              <td>{[log.location_city, log.location_country].filter(Boolean).join(", ") || "–"}</td>
              <td>{[log.device_os, log.device_browser].filter(Boolean).join(" / ") || "–"}</td>
              <td><RiskBadge level={log.risk_level} /></td>
              <td>{log.conditional_access_status || "–"}</td>
              <td>{log.status_error_code === 0 ? "✓" : `✗ ${log.status_error_code}`}</td>
            </tr>
          ))}
          {logs.length === 0 && (
            <tr><td colSpan={8} className="loading">No sign-in logs found</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

/* ── Audit Logs tab ────────────────────────────────────── */

const RISKY_AUDIT_KEYWORDS = [
  "delete", "remove", "disable", "reset password", "add member to role",
  "add eligible member", "consent to application", "add service principal",
  "fraud", "security info", "conditional access",
];

function isRiskyAudit(log: AuditLogSummary): boolean {
  if (log.result !== "success") return true;
  const name = (log.activity_display_name || "").toLowerCase();
  return RISKY_AUDIT_KEYWORDS.some((kw) => name.includes(kw));
}

function AuditLogsTab({ logs, isLoading }: { logs: AuditLogSummary[]; isLoading: boolean }) {
  if (isLoading) return <p className="loading">Loading logs…</p>;
  return (
    <div className="table-wrapper">
      <table className="nested-table">
        <thead>
          <tr><th>Time</th><th>Activity</th><th>Category</th><th>Initiated By</th><th>Result</th><th>Reason</th></tr>
        </thead>
        <tbody>
          {logs.map((log) => (
            <tr key={log.id} style={isRiskyAudit(log) ? RISKY_ROW_STYLE : undefined}>
              <td>{fmtDate(log.activity_datetime)}</td>
              <td>{log.activity_display_name}</td>
              <td>{log.category || "–"}</td>
              <td>{log.initiated_by_user || log.initiated_by_app || "–"}</td>
              <td>
                <span className={`badge ${log.result === "success" ? "badge-info" : "badge-critical"}`}>
                  {log.result}
                </span>
              </td>
              <td>{log.result_reason || "–"}</td>
            </tr>
          ))}
          {logs.length === 0 && (
            <tr><td colSpan={6} className="loading">No audit logs found</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

/* ── Activity Logs tab ─────────────────────────────────── */

const RISKY_OPERATIONS = new Set([
  "FileDeleted", "FileDeletedFirstStageRecycleBin", "FileDeletedSecondStageRecycleBin",
  "FolderDeletedSecondStageRecycleBin", "AnonymousLinkCreated",
  "SiteCollectionAdminAdded", "SiteAdminChangeRequest",
  "FileSyncDownloadedFull", "FileMalwareDetected",
]);

function isRiskyActivity(log: ActivityLogSummary): boolean {
  if (RISKY_OPERATIONS.has(log.operation)) return true;
  if (log.result_status && log.result_status.toLowerCase() !== "succeeded" && log.result_status.toLowerCase() !== "true") return true;
  return false;
}

function ActivityLogsTab({ logs, isLoading }: { logs: ActivityLogSummary[]; isLoading: boolean }) {
  if (isLoading) return <p className="loading">Loading logs…</p>;
  return (
    <div className="table-wrapper">
      <table className="nested-table">
        <thead>
          <tr><th>Time</th><th>Operation</th><th>Source</th><th>Workload</th><th>Object</th><th>File</th><th>IP</th><th>Status</th></tr>
        </thead>
        <tbody>
          {logs.map((log) => (
            <tr key={log.id} style={isRiskyActivity(log) ? RISKY_ROW_STYLE : undefined}>
              <td>{fmtDate(log.creation_time)}</td>
              <td>{log.operation}</td>
              <td>{log.source || "–"}</td>
              <td>{log.workload || "–"}</td>
              <td title={log.object_id} style={{ maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {log.object_id || "–"}
              </td>
              <td>{log.source_file_name || "–"}</td>
              <td>{log.client_ip || "–"}</td>
              <td>{log.result_status || "–"}</td>
            </tr>
          ))}
          {logs.length === 0 && (
            <tr><td colSpan={8} className="loading">No activity logs found</td></tr>
          )}
        </tbody>
      </table>
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
