import { useEffect, useRef, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  fetchCAPolicies,
  fetchCAPolicy,
  fetchCAPolicyStats,
  fetchCACoverage,
  fetchCACoverageGaps,
  fetchCACoverageSummary,
  fetchNamedLocations,
  fetchAuthStrengths,
  fetchDirectoryEntries,
  syncCAPolicies,
  type CAPolicy,
  type CoverageGap,
  type CoverageByEntity,
  type CoverageSummary,
  type NamedLocationEntry,
  type AuthStrengthEntry,
  type DirectoryEntry,
  type CAPolicyStats,
} from "../api";

/* ── Mermaid dynamic import ────────────────────────────────── */
let mermaidReady: Promise<typeof import("mermaid")> | null = null;
function getMermaid() {
  if (!mermaidReady) {
    mermaidReady = import("mermaid").then((m) => {
      m.default.initialize({ startOnLoad: false, theme: "dark" });
      return m;
    });
  }
  return mermaidReady;
}

/* ── Tab constants ─────────────────────────────────────────── */
const TABS = ["Policies", "Coverage Map", "Reference Data"] as const;
type Tab = (typeof TABS)[number];

/* ── State badge helpers ───────────────────────────────────── */
function stateBadge(state: string) {
  const cls =
    state === "enabled"
      ? "badge badge-success"
      : state === "disabled"
        ? "badge badge-muted"
        : "badge badge-warning";
  return <span className={cls}>{state}</span>;
}

function inclusionBadge(t: string) {
  return (
    <span className={t === "include" ? "badge badge-info" : "badge badge-danger"}>
      {t}
    </span>
  );
}

/* ================================================================ */
/*  Main Page Component                                             */
/* ================================================================ */

export default function CAPolicies() {
  const [tab, setTab] = useState<Tab>("Policies");
  const queryClient = useQueryClient();

  /* ── Sync mutation ──────────────────────────────────────── */
  const syncMut = useMutation({
    mutationFn: syncCAPolicies,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ca"] });
    },
  });

  /* ── Stats (shown in KPI strip) ─────────────────────────── */
  const statsQ = useQuery({
    queryKey: ["ca", "stats"],
    queryFn: fetchCAPolicyStats,
  });

  const stats: CAPolicyStats | undefined = statsQ.data;

  return (
    <div className="ca-page">
      {/* ── KPI strip ──────────────────────────────────────── */}
      <div className="kpi-strip">
        <div className="kpi-card">
          <div className="kpi-value">{stats?.total_policies ?? "–"}</div>
          <div className="kpi-label">Policies</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-value">{stats?.by_state?.enabled ?? "–"}</div>
          <div className="kpi-label">Enabled</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-value">{stats?.named_locations ?? "–"}</div>
          <div className="kpi-label">Named Locations</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-value">{stats?.auth_strengths ?? "–"}</div>
          <div className="kpi-label">Auth Strengths</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-value">{stats?.directory_entries ?? "–"}</div>
          <div className="kpi-label">Directory Entries</div>
        </div>
      </div>

      {/* ── Sync button ────────────────────────────────────── */}
      <div className="ca-toolbar">
        <button
          className="btn btn-primary"
          disabled={syncMut.isPending}
          onClick={() => syncMut.mutate()}
        >
          {syncMut.isPending ? "Syncing…" : "Sync from Graph"}
        </button>
        {syncMut.isSuccess && (
          <span className="badge badge-success" style={{ marginLeft: 8 }}>
            Synced: {Object.entries(syncMut.data.synced).map(([k, v]) => `${k}=${v}`).join(", ")}
          </span>
        )}
        {syncMut.isError && (
          <span className="badge badge-danger" style={{ marginLeft: 8 }}>
            {(syncMut.error as Error).message}
          </span>
        )}
      </div>

      {/* ── Tab bar ────────────────────────────────────────── */}
      <div className="tab-bar">
        {TABS.map((t) => (
          <button
            key={t}
            className={`tab-btn ${t === tab ? "active" : ""}`}
            onClick={() => setTab(t)}
          >
            {t}
          </button>
        ))}
      </div>

      {/* ── Tab content ────────────────────────────────────── */}
      {tab === "Policies" && <PoliciesTab />}
      {tab === "Coverage Map" && <CoverageTab />}
      {tab === "Reference Data" && <ReferenceTab />}
    </div>
  );
}

/* ================================================================ */
/*  Policies Tab                                                    */
/* ================================================================ */

function PoliciesTab() {
  const [stateFilter, setStateFilter] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const policiesQ = useQuery({
    queryKey: ["ca", "policies", stateFilter],
    queryFn: () =>
      fetchCAPolicies(stateFilter ? { state: stateFilter, limit: "200" } : { limit: "200" }),
  });

  return (
    <div>
      <div className="filter-row">
        <label>
          State:{" "}
          <select value={stateFilter} onChange={(e) => setStateFilter(e.target.value)}>
            <option value="">All</option>
            <option value="enabled">Enabled</option>
            <option value="disabled">Disabled</option>
            <option value="enabledForReportingButNotEnforced">Report-only</option>
          </select>
        </label>
        <span className="filter-info">
          {policiesQ.data?.total ?? 0} policies
        </span>
      </div>

      <table className="data-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>State</th>
            <th>Grant Controls</th>
            <th>Modified</th>
          </tr>
        </thead>
        <tbody>
          {policiesQ.data?.items.map((p) => (
            <PolicyRow
              key={p.id}
              policy={p}
              isExpanded={expandedId === p.id}
              onToggle={() => setExpandedId(expandedId === p.id ? null : p.id)}
            />
          ))}
          {policiesQ.isLoading && (
            <tr>
              <td colSpan={4} className="center-text">Loading…</td>
            </tr>
          )}
          {policiesQ.data?.items.length === 0 && (
            <tr>
              <td colSpan={4} className="center-text">No policies cached. Click "Sync from Graph" to fetch.</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function PolicyRow({
  policy,
  isExpanded,
  onToggle,
}: {
  policy: CAPolicy;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const grant = policy.grant_controls || {};
  const builtIn = (grant.builtInControls as string[]) || [];

  return (
    <>
      <tr className="clickable-row" onClick={onToggle}>
        <td>{policy.display_name}</td>
        <td>{stateBadge(policy.state)}</td>
        <td>{builtIn.join(", ") || "—"}</td>
        <td>{policy.modified_date_time?.slice(0, 10) ?? "—"}</td>
      </tr>
      {isExpanded && <PolicyDetail policyId={policy.id} />}
    </>
  );
}

function PolicyDetail({ policyId }: { policyId: string }) {
  const detailQ = useQuery({
    queryKey: ["ca", "policy", policyId],
    queryFn: () => fetchCAPolicy(policyId),
  });
  const mermaidRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!detailQ.data || !mermaidRef.current) return;
    const pol = detailQ.data;
    const diagram = buildPolicyDiagram(pol);

    let cancelled = false;
    getMermaid().then(async (m) => {
      if (cancelled || !mermaidRef.current) return;
      try {
        const { svg } = await m.default.render(`mermaid-${policyId.replace(/[^a-zA-Z0-9]/g, "")}`, diagram);
        if (!cancelled && mermaidRef.current) {
          mermaidRef.current.innerHTML = svg;
        }
      } catch {
        if (mermaidRef.current) mermaidRef.current.textContent = diagram;
      }
    });

    return () => { cancelled = true; };
  }, [detailQ.data, policyId]);

  if (detailQ.isLoading) return <tr><td colSpan={4}>Loading detail…</td></tr>;
  if (!detailQ.data) return null;

  const pol = detailQ.data;
  const conditions = pol.conditions || {};
  const users = (conditions.users as Record<string, unknown>) || {};
  const apps = (conditions.applications as Record<string, unknown>) || {};

  return (
    <tr className="expanded-row">
      <td colSpan={4}>
        <div className="policy-detail">
          <div className="detail-grid">
            <div className="detail-section">
              <h4>Users / Groups</h4>
              <ConditionList label="Include Users" items={users.includeUsers as string[]} />
              <ConditionList label="Exclude Users" items={users.excludeUsers as string[]} />
              <ConditionList label="Include Groups" items={users.includeGroups as string[]} />
              <ConditionList label="Exclude Groups" items={users.excludeGroups as string[]} />
              <ConditionList label="Include Roles" items={users.includeRoles as string[]} />
              <ConditionList label="Exclude Roles" items={users.excludeRoles as string[]} />
            </div>
            <div className="detail-section">
              <h4>Applications</h4>
              <ConditionList label="Include" items={apps.includeApplications as string[]} />
              <ConditionList label="Exclude" items={apps.excludeApplications as string[]} />
            </div>
            <div className="detail-section">
              <h4>Grant Controls</h4>
              <pre className="json-block">{JSON.stringify(pol.grant_controls, null, 2)}</pre>
            </div>
            <div className="detail-section">
              <h4>Session Controls</h4>
              <pre className="json-block">{JSON.stringify(pol.session_controls, null, 2)}</pre>
            </div>
          </div>
          {/* Coverage entries */}
          {pol.coverage && pol.coverage.length > 0 && (
            <div className="detail-section">
              <h4>Coverage Entries ({pol.coverage.length})</h4>
              <table className="data-table nested-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Entity</th>
                    <th>Include/Exclude</th>
                  </tr>
                </thead>
                <tbody>
                  {pol.coverage.map((c, i) => (
                    <tr key={i}>
                      <td>{c.entity_type}</td>
                      <td>{c.entity_display_name || c.entity_id}</td>
                      <td>{inclusionBadge(c.inclusion_type)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {/* Mermaid flow diagram */}
          <div className="detail-section">
            <h4>Policy Flow</h4>
            <div className="mermaid-container" ref={mermaidRef}>Rendering…</div>
          </div>
        </div>
      </td>
    </tr>
  );
}

function ConditionList({ label, items }: { label: string; items?: string[] }) {
  if (!items || items.length === 0) return null;
  return (
    <div className="condition-item">
      <strong>{label}:</strong> {items.join(", ")}
    </div>
  );
}

/* ── Mermaid diagram builder ──────────────────────────────── */
function buildPolicyDiagram(pol: CAPolicy): string {
  const conditions = pol.conditions || {};
  const users = (conditions.users as Record<string, unknown>) || {};
  const apps = (conditions.applications as Record<string, unknown>) || {};
  const grant = pol.grant_controls || {};
  const platforms = (conditions.platforms as Record<string, unknown>) || {};
  const locations = (conditions.locations as Record<string, unknown>) || {};

  const safe = (s: string) => s.replace(/[[\](){}#&;]/g, " ").trim();
  const lines: string[] = ["flowchart LR"];

  lines.push(`  P["${safe(pol.display_name)}"]`);

  // Users
  const incUsers = (users.includeUsers as string[]) || [];
  const incGroups = (users.includeGroups as string[]) || [];
  if (incUsers.length || incGroups.length) {
    const label = [...incUsers, ...incGroups].slice(0, 4).join(", ");
    lines.push(`  U["Users: ${safe(label)}"]`);
    lines.push("  U --> P");
  }

  // Apps
  const incApps = (apps.includeApplications as string[]) || [];
  if (incApps.length) {
    const label = incApps.slice(0, 3).join(", ");
    lines.push(`  A["Apps: ${safe(label)}"]`);
    lines.push("  A --> P");
  }

  // Platforms
  const incPlatforms = (platforms.includePlatforms as string[]) || [];
  if (incPlatforms.length) {
    lines.push(`  PL["Platforms: ${safe(incPlatforms.join(", "))}"]`);
    lines.push("  PL --> P");
  }

  // Locations
  const incLocations = (locations.includeLocations as string[]) || [];
  if (incLocations.length) {
    lines.push(`  L["Locations: ${safe(incLocations.slice(0, 3).join(", "))}"]`);
    lines.push("  L --> P");
  }

  // Grant controls
  const builtIn = (grant.builtInControls as string[]) || [];
  if (builtIn.length) {
    lines.push(`  G["Grant: ${safe(builtIn.join(", "))}"]`);
    lines.push("  P --> G");
  }

  // State
  lines.push(`  S["State: ${pol.state}"]`);
  lines.push("  P --> S");

  return lines.join("\n");
}

/* ================================================================ */
/*  Coverage Map Tab                                                */
/* ================================================================ */

function CoverageTab() {
  const summaryQ = useQuery({
    queryKey: ["ca", "coverage-summary"],
    queryFn: fetchCACoverageSummary,
  });
  const gapsQ = useQuery({
    queryKey: ["ca", "coverage-gaps"],
    queryFn: fetchCACoverageGaps,
  });
  const coverageQ = useQuery({
    queryKey: ["ca", "coverage"],
    queryFn: () => fetchCACoverage(),
  });

  const summary = summaryQ.data;
  const gaps = gapsQ.data?.gaps ?? [];

  return (
    <div>
      {/* Summary cards */}
      {summary && (
        <div className="coverage-summary-grid">
          {Object.entries(summary.entity_coverage).map(([type, counts]) => (
            <div key={type} className="kpi-card">
              <div className="kpi-value">{counts.included ?? 0}</div>
              <div className="kpi-label">{type} (included)</div>
              {(counts.excluded ?? 0) > 0 && (
                <div className="kpi-sub">
                  {counts.excluded} excluded
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Coverage by entity */}
      <h3>Coverage by Entity</h3>
      {coverageQ.isLoading && <p>Loading…</p>}
      {coverageQ.data && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Type</th>
              <th>Entity</th>
              <th>Policies</th>
            </tr>
          </thead>
          <tbody>
            {coverageQ.data.by_entity.map((e: CoverageByEntity, i: number) => (
              <tr key={i}>
                <td>{e.entity_type}</td>
                <td>{e.entity_display_name || e.entity_id}</td>
                <td>
                  {e.policies.map((p, j) => (
                    <span key={j} className="policy-chip">
                      {p.policy_id.slice(0, 8)}… {inclusionBadge(p.inclusion_type)}
                    </span>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {/* Gap analysis */}
      <h3>Coverage Gaps ({gaps.length})</h3>
      {gapsQ.isLoading && <p>Loading…</p>}
      {gaps.length === 0 && !gapsQ.isLoading && <p>No issues detected.</p>}
      {gaps.length > 0 && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Policy</th>
              <th>State</th>
              <th>Issues</th>
            </tr>
          </thead>
          <tbody>
            {gaps.map((g: CoverageGap) => (
              <tr key={g.policy_id}>
                <td>{g.display_name}</td>
                <td>{stateBadge(g.state)}</td>
                <td>
                  <ul className="gap-issues">
                    {g.issues.map((issue, j) => (
                      <li key={j}>{issue}</li>
                    ))}
                  </ul>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

/* ================================================================ */
/*  Reference Data Tab                                              */
/* ================================================================ */

function ReferenceTab() {
  const [subTab, setSubTab] = useState<"locations" | "strengths" | "directory">("locations");

  return (
    <div>
      <div className="sub-tab-bar">
        <button className={`tab-btn ${subTab === "locations" ? "active" : ""}`} onClick={() => setSubTab("locations")}>
          Named Locations
        </button>
        <button className={`tab-btn ${subTab === "strengths" ? "active" : ""}`} onClick={() => setSubTab("strengths")}>
          Auth Strengths
        </button>
        <button className={`tab-btn ${subTab === "directory" ? "active" : ""}`} onClick={() => setSubTab("directory")}>
          Directory Entries
        </button>
      </div>

      {subTab === "locations" && <LocationsTable />}
      {subTab === "strengths" && <StrengthsTable />}
      {subTab === "directory" && <DirectoryTable />}
    </div>
  );
}

function LocationsTable() {
  const q = useQuery({ queryKey: ["ca", "locations"], queryFn: fetchNamedLocations });
  if (q.isLoading) return <p>Loading…</p>;

  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Type</th>
          <th>Trusted</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>
        {q.data?.items.map((loc: NamedLocationEntry) => (
          <tr key={loc.id}>
            <td>{loc.display_name}</td>
            <td>{loc.location_type}</td>
            <td>{loc.is_trusted ? "✓" : "✗"}</td>
            <td>
              {loc.ip_ranges?.length > 0 && <span>{loc.ip_ranges.length} IP ranges</span>}
              {loc.countries_and_regions?.length > 0 && (
                <span>{loc.countries_and_regions.join(", ")}</span>
              )}
            </td>
          </tr>
        ))}
        {q.data?.items.length === 0 && (
          <tr><td colSpan={4} className="center-text">No locations cached</td></tr>
        )}
      </tbody>
    </table>
  );
}

function StrengthsTable() {
  const q = useQuery({ queryKey: ["ca", "strengths"], queryFn: fetchAuthStrengths });
  if (q.isLoading) return <p>Loading…</p>;

  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Type</th>
          <th>Requirements</th>
          <th>Combinations</th>
        </tr>
      </thead>
      <tbody>
        {q.data?.items.map((a: AuthStrengthEntry) => (
          <tr key={a.id}>
            <td>{a.display_name}</td>
            <td>{a.policy_type}</td>
            <td>{a.requirements_satisfied}</td>
            <td>
              <span className="badge badge-info">{a.allowed_combinations.length}</span>
            </td>
          </tr>
        ))}
        {q.data?.items.length === 0 && (
          <tr><td colSpan={4} className="center-text">No auth strengths cached</td></tr>
        )}
      </tbody>
    </table>
  );
}

function DirectoryTable() {
  const q = useQuery({ queryKey: ["ca", "directory"], queryFn: () => fetchDirectoryEntries() });
  if (q.isLoading) return <p>Loading…</p>;

  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Type</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        {q.data?.items.map((e: DirectoryEntry) => (
          <tr key={e.id}>
            <td>{e.display_name}</td>
            <td>{e.object_type}</td>
            <td>{e.description || "—"}</td>
          </tr>
        ))}
        {q.data?.items.length === 0 && (
          <tr><td colSpan={3} className="center-text">No directory entries cached</td></tr>
        )}
      </tbody>
    </table>
  );
}
