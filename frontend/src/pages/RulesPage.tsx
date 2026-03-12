import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { fetchRules, patchRule, deleteRule, type RuleEntry, type PaginatedResponse } from "../api";
import JsonView from "../components/JsonView";
import SortableTable, { type ColumnDef } from "../components/SortableTable";

const PAGE_SIZE = 50;

export default function RulesPage() {
  const [offset, setOffset] = useState(0);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const queryClient = useQueryClient();

  const { data, isLoading, error } = useQuery<PaginatedResponse<RuleEntry>>({
    queryKey: ["rules", offset],
    queryFn: () => fetchRules({ offset: String(offset), limit: String(PAGE_SIZE) }),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) =>
      patchRule(id, { enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["rules"] }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => deleteRule(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["rules"] }),
  });

  const total = data?.total ?? 0;
  const items = data?.items ?? [];

  const columns: ColumnDef<RuleEntry>[] = [
    {
      key: "name",
      header: "Name",
      filterable: true,
      value: (r) => r.name,
      render: (r) => (
        <div>
          <div style={{ fontWeight: 600 }}>{r.name}</div>
          {r.description && (
            <div style={{ color: "var(--text-secondary)", fontSize: "0.8rem", marginTop: "0.15rem" }}>
              {r.description}
            </div>
          )}
        </div>
      ),
    },
    {
      key: "category",
      header: "Category",
      groupable: true,
      filterable: true,
      value: (r) => r.category || "–",
    },
    {
      key: "severity",
      header: "Severity",
      groupable: true,
      filterable: true,
      value: (r) => r.severity,
      render: (r) => <span className={`badge badge-${r.severity}`}>{r.severity}</span>,
    },
    {
      key: "risk_points",
      header: "Risk Pts",
      value: (r) => r.risk_points,
    },
    {
      key: "watch_window_days",
      header: "Window (d)",
      value: (r) => r.watch_window_days,
      render: (r) => String(r.watch_window_days ?? "–"),
    },
    {
      key: "mitre",
      header: "MITRE",
      filterable: true,
      value: (r) => r.mitre_tactics?.join(", ") || "",
      render: (r) =>
        r.mitre_tactics && r.mitre_tactics.length > 0 ? (
          <span title={[...r.mitre_tactics, ...(r.mitre_techniques || [])].join(", ")}>
            {r.mitre_tactics.join(", ")}
          </span>
        ) : (
          "–"
        ),
    },
    {
      key: "type",
      header: "Type",
      groupable: true,
      value: (r) => (r.is_system ? "System" : "Custom"),
      render: (r) =>
        r.is_system ? (
          <span className="badge badge-info" title="System rule">System</span>
        ) : (
          "Custom"
        ),
    },
    {
      key: "enabled",
      header: "Enabled",
      groupable: true,
      value: (r) => r.enabled,
      render: (r) => (
        <label className="toggle" onClick={(e) => e.stopPropagation()}>
          <input
            type="checkbox"
            checked={r.enabled}
            onChange={() => toggleMutation.mutate({ id: r.id, enabled: !r.enabled })}
            disabled={toggleMutation.isPending}
          />
          <span className="slider" />
        </label>
      ),
    },
    {
      key: "actions",
      header: "",
      sortable: false,
      value: () => "",
      render: (r) =>
        !r.is_system ? (
          <button
            className="btn btn-sm btn-danger"
            onClick={(e) => {
              e.stopPropagation();
              if (confirm(`Delete rule "${r.name}"?`)) {
                deleteMutation.mutate(r.id);
              }
            }}
            disabled={deleteMutation.isPending}
          >
            Delete
          </button>
        ) : null,
    },
  ];

  return (
    <div>
      <h1 className="page-heading">Detection Rules</h1>
      <p className="page-subtitle">Manage correlation rules that analyze logs and generate security incidents</p>

      {error && <div className="error-box">{String(error)}</div>}

      <div className="card">
        {isLoading ? (
          <p className="loading">Loading…</p>
        ) : (
          <SortableTable
            columns={columns}
            data={items}
            rowKey={(r) => r.id}
            expandedKey={expandedId}
            onToggleExpand={(key) => setExpandedId(expandedId === key ? null : (key as number))}
            renderExpanded={(r) => <RuleDetails rule={r} />}
            defaultSort={{ key: "name", dir: "asc" }}
          />
        )}

        <Pagination offset={offset} total={total} pageSize={PAGE_SIZE} onChange={setOffset} />
      </div>
    </div>
  );
}

/* ── Expanded rule detail panel ──────────────────────────── */

function RuleDetails({ rule: r }: { rule: RuleEntry }) {
  return (
    <div className="user-detail-panel">
      {r.description && (
        <div className="risk-alert" style={{ marginBottom: "1rem" }}>
          <strong>Description:</strong>
          <p style={{ margin: "0.25rem 0 0" }}>{r.description}</p>
        </div>
      )}

      <div className="detail-grid">
        {/* Overview */}
        <div className="detail-section">
          <h4>Rule Overview</h4>
          <table className="nested-table">
            <tbody>
              <tr><td><strong>Slug</strong></td><td style={{ fontFamily: "monospace" }}>{r.slug}</td></tr>
              <tr><td><strong>Category</strong></td><td>{r.category || "–"}</td></tr>
              <tr><td><strong>Severity</strong></td><td><span className={`badge badge-${r.severity}`}>{r.severity}</span></td></tr>
              <tr><td><strong>Risk Points</strong></td><td>{r.risk_points} pts</td></tr>
              <tr><td><strong>Type</strong></td><td>{r.is_system ? "System (built-in)" : "Custom"}</td></tr>
              <tr><td><strong>Enabled</strong></td><td>{r.enabled ? "Yes" : "No"}</td></tr>
            </tbody>
          </table>
        </div>

        {/* Watch Window */}
        <div className="detail-section">
          <h4>Watch Window</h4>
          {r.watch_window?.enabled ? (
            <table className="nested-table">
              <tbody>
                <tr><td><strong>Duration</strong></td><td>{r.watch_window.duration_days} day(s)</td></tr>
                <tr><td><strong>Risk Points</strong></td><td>{r.watch_window.risk_points} pts per window</td></tr>
              </tbody>
            </table>
          ) : (
            <p style={{ color: "var(--text-secondary)" }}>Watch window not enabled for this rule.</p>
          )}
        </div>

        {/* MITRE ATT&CK */}
        {(r.mitre_tactics?.length > 0 || r.mitre_techniques?.length > 0) && (
          <div className="detail-section">
            <h4>MITRE ATT&CK</h4>
            <table className="nested-table">
              <tbody>
                {r.mitre_tactics.length > 0 && (
                  <tr>
                    <td><strong>Tactics</strong></td>
                    <td>{r.mitre_tactics.map((t, i) => (
                      <span key={i} className="badge badge-info" style={{ marginRight: "0.35rem" }}>{t}</span>
                    ))}</td>
                  </tr>
                )}
                {r.mitre_techniques.length > 0 && (
                  <tr>
                    <td><strong>Techniques</strong></td>
                    <td>{r.mitre_techniques.map((t, i) => (
                      <span key={i} style={{ fontFamily: "monospace", marginRight: "0.5rem" }}>{t}</span>
                    ))}</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* Trigger Conditions */}
        {r.triggers && r.triggers.length > 0 && (
          <div className="detail-section" style={{ gridColumn: "1 / -1" }}>
            <h4>Trigger Conditions</h4>
            <p style={{ color: "var(--text-secondary)", fontSize: "0.8rem", margin: "0 0 0.5rem" }}>
              When any of these triggers match an incoming log event, the rule fires (OR logic between triggers, AND logic within each trigger's conditions).
            </p>
            <table className="nested-table">
              <thead>
                <tr><th>Log Source</th><th>Conditions (all must match)</th></tr>
              </thead>
              <tbody>
                {r.triggers.map((t, i) => (
                  <tr key={i}>
                    <td><span className="badge badge-info">{t.source}</span></td>
                    <td>
                      {t.conditions.length > 0 ? (
                        <ul style={{ margin: 0, paddingLeft: "1.2rem" }}>
                          {t.conditions.map((c, j) => (
                            <li key={j} style={{ fontFamily: "monospace", fontSize: "0.82rem" }}>{c}</li>
                          ))}
                        </ul>
                      ) : (
                        <span style={{ color: "var(--text-secondary)" }}>Any event from this source</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Threshold */}
        {r.threshold && (
          <div className="detail-section" style={{ gridColumn: "1 / -1" }}>
            <h4>Threshold Condition</h4>
            <p style={{ color: "var(--text-secondary)", fontSize: "0.8rem", margin: "0 0 0.5rem" }}>
              The trigger event must also exceed this aggregation threshold within the specified time window.
            </p>
            <div style={{
              background: "var(--bg-primary)",
              border: "1px solid var(--border-color)",
              borderRadius: "var(--radius)",
              padding: "0.75rem 1rem",
              fontFamily: "monospace",
              fontSize: "0.85rem",
            }}>
              {r.threshold}
            </div>
          </div>
        )}

        {/* Correlations */}
        {r.correlations && r.correlations.length > 0 && (
          <div className="detail-section" style={{ gridColumn: "1 / -1" }}>
            <h4>Correlation Conditions</h4>
            <p style={{ color: "var(--text-secondary)", fontSize: "0.8rem", margin: "0 0 0.5rem" }}>
              A secondary event from another log source must also occur within the time window for the rule to fire.
            </p>
            <table className="nested-table">
              <thead>
                <tr><th>Secondary Source</th><th>Direction</th><th>Window</th><th>Conditions</th></tr>
              </thead>
              <tbody>
                {r.correlations.map((c, i) => (
                  <tr key={i}>
                    <td><span className="badge badge-info">{c.source}</span></td>
                    <td>{c.direction}</td>
                    <td>{c.window_minutes} min</td>
                    <td>
                      <ul style={{ margin: 0, paddingLeft: "1.2rem" }}>
                        {c.conditions.map((cond, j) => (
                          <li key={j} style={{ fontFamily: "monospace", fontSize: "0.82rem" }}>{cond}</li>
                        ))}
                      </ul>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Meta-Rule */}
        {r.meta_rule && (
          <div className="detail-section" style={{ gridColumn: "1 / -1" }}>
            <h4>Meta-Rule Configuration</h4>
            <p style={{ color: "var(--text-secondary)", fontSize: "0.8rem", margin: "0 0 0.5rem" }}>
              This meta-rule fires when a user has multiple active watch windows from other rules, indicating a multi-signal compromise pattern.
            </p>
            <table className="nested-table">
              <tbody>
                <tr>
                  <td><strong>Minimum Active Windows</strong></td>
                  <td>{r.meta_rule.min_active_windows}</td>
                </tr>
                <tr>
                  <td><strong>Required Rules</strong></td>
                  <td>
                    {r.meta_rule.required_rule_slugs.length > 0 ? (
                      <ul style={{ margin: 0, paddingLeft: "1.2rem" }}>
                        {r.meta_rule.required_rule_slugs.map((s, i) => (
                          <li key={i} style={{ fontFamily: "monospace" }}>{s}</li>
                        ))}
                      </ul>
                    ) : (
                      <span style={{ color: "var(--text-secondary)" }}>Any rules (no specific rules required)</span>
                    )}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        )}

        {/* Raw Rule JSON */}
        <div className="detail-section" style={{ gridColumn: "1 / -1" }}>
          <h4>Raw Rule Definition (JSON DSL)</h4>
          <JsonView data={r.rule_json} initialExpanded={false} />
        </div>
      </div>
    </div>
  );
}

/* ── Helpers ──────────────────────────────────────────────── */

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
