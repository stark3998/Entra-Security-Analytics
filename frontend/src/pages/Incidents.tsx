import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { fetchIncidents, patchIncident, fetchEvent, type IncidentEntry, type PaginatedResponse, type EventLookupResult } from "../api";
import JsonView from "../components/JsonView";
import SortableTable, { type ColumnDef } from "../components/SortableTable";

const PAGE_SIZE = 50;
const STATUS_OPTIONS = ["", "open", "investigating", "resolved", "closed", "false_positive"];

export default function Incidents() {
  const [offset, setOffset] = useState(0);
  const [statusFilter, setStatusFilter] = useState("");
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const queryClient = useQueryClient();

  const params: Record<string, string> = {
    offset: String(offset),
    limit: String(PAGE_SIZE),
  };
  if (statusFilter) params.status = statusFilter;

  const { data, isLoading, error } = useQuery<PaginatedResponse<IncidentEntry>>({
    queryKey: ["incidents", offset, statusFilter],
    queryFn: () => fetchIncidents(params),
  });

  const resolveMutation = useMutation({
    mutationFn: (id: number) => patchIncident(id, { status: "resolved" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["incidents"] }),
  });

  const total = data?.total ?? 0;
  const items = data?.items ?? [];

  const columns: ColumnDef<IncidentEntry>[] = [
    {
      key: "id",
      header: "ID",
      value: (inc) => inc.id,
    },
    {
      key: "created_at",
      header: "Created",
      value: (inc) => inc.created_at,
      render: (inc) => fmtDate(inc.created_at),
    },
    {
      key: "severity",
      header: "Severity",
      groupable: true,
      value: (inc) => inc.severity,
      render: (inc) => <span className={`badge badge-${inc.severity}`}>{inc.severity}</span>,
    },
    {
      key: "rule_name",
      header: "Rule",
      groupable: true,
      value: (inc) => inc.rule_name || inc.rule_slug,
      render: (inc) => <span title={inc.rule_slug}>{inc.rule_name || inc.rule_slug}</span>,
    },
    {
      key: "user",
      header: "User",
      groupable: true,
      value: (inc) => inc.user_display_name || inc.user_id,
    },
    {
      key: "status",
      header: "Status",
      groupable: true,
      value: (inc) => inc.status,
      render: (inc) => <span className={`badge badge-${inc.status}`}>{inc.status}</span>,
    },
    {
      key: "mitre",
      header: "MITRE",
      groupable: true,
      value: (inc) => inc.mitre_tactic || "",
      render: (inc) =>
        inc.mitre_tactic ? `${inc.mitre_tactic} / ${inc.mitre_technique}` : "–",
    },
    {
      key: "actions",
      header: "Actions",
      sortable: false,
      value: () => "",
      render: (inc) =>
        inc.status === "open" ? (
          <button
            className="btn btn-sm btn-primary"
            onClick={(e) => {
              e.stopPropagation();
              resolveMutation.mutate(inc.id);
            }}
            disabled={resolveMutation.isPending}
          >
            Resolve
          </button>
        ) : null,
    },
  ];

  return (
    <div>
      <h1 className="page-heading">Security Incidents</h1>
      <p className="page-subtitle">Correlated alerts triggered by detection rules — triage, investigate, and resolve threats</p>

      <div className="filters">
        <select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setOffset(0); }}>
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>{s || "All Statuses"}</option>
          ))}
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
            rowKey={(inc) => inc.id}
            expandedKey={expandedId}
            onToggleExpand={(key) => setExpandedId(expandedId === key ? null : (key as number))}
            renderExpanded={(inc) => <IncidentDetails inc={inc} />}
            defaultSort={{ key: "created_at", dir: "desc" }}
          />
        )}

        <Pagination offset={offset} total={total} pageSize={PAGE_SIZE} onChange={setOffset} />
      </div>
    </div>
  );
}

/* ── Expanded details panel ────────────────────────────── */

function IncidentDetails({ inc }: { inc: IncidentEntry }) {
  const evidence = inc.evidence as string[] | null;
  const [expandedEvent, setExpandedEvent] = useState<string | null>(null);

  return (
    <div className="user-detail-panel">
      {inc.title && (
        <h4 style={{ margin: "0 0 0.5rem" }}>{inc.title}</h4>
      )}
      {inc.description && (
        <div className="risk-alert" style={{ marginBottom: "1rem" }}>
          <strong>Description:</strong>
          <div
            style={{ margin: "0.25rem 0 0", whiteSpace: "pre-wrap", lineHeight: 1.6 }}
            dangerouslySetInnerHTML={{ __html: renderSimpleMarkdown(inc.description) }}
          />
        </div>
      )}

      <div className="detail-grid">
        <div className="detail-section">
          <h4>Score & Reasoning</h4>
          <table className="nested-table">
            <tbody>
              <tr>
                <td><strong>Risk Score at Creation</strong></td>
                <td>
                  <span className={`badge badge-${inc.severity}`}>
                    {inc.risk_score_contribution} pts
                  </span>
                </td>
              </tr>
              {inc.rule_risk_points != null && (
                <tr><td><strong>Rule Risk Points</strong></td><td>{inc.rule_risk_points} pts</td></tr>
              )}
              {inc.rule_category && (
                <tr><td><strong>Rule Category</strong></td><td>{inc.rule_category}</td></tr>
              )}
              {inc.rule_description && (
                <tr><td><strong>Rule Description</strong></td><td>{inc.rule_description}</td></tr>
              )}
              {inc.rule_name && (
                <tr>
                  <td><strong>Rule</strong></td>
                  <td>
                    <a href="/rules" style={{ color: "var(--accent)", textDecoration: "none" }}>
                      {inc.rule_name}
                    </a>
                    {inc.rule_slug && (
                      <span style={{ color: "var(--text-secondary)", marginLeft: "0.5rem", fontFamily: "monospace", fontSize: "0.85rem" }}>
                        ({inc.rule_slug})
                      </span>
                    )}
                  </td>
                </tr>
              )}
              {inc.mitre_tactic && (
                <tr><td><strong>MITRE ATT&CK</strong></td><td>{inc.mitre_tactic}{inc.mitre_technique ? ` / ${inc.mitre_technique}` : ""}</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="detail-section">
          <h4>Evidence (Correlated Events)</h4>
          {evidence && evidence.length > 0 ? (
            <table className="nested-table">
              <thead>
                <tr><th></th><th>Event ID</th></tr>
              </thead>
              <tbody>
                {evidence.map((eid, i) => (
                  <EvidenceEventRow
                    key={i}
                    eventId={eid}
                    isExpanded={expandedEvent === eid}
                    onToggle={() => setExpandedEvent(expandedEvent === eid ? null : eid)}
                  />
                ))}
              </tbody>
            </table>
          ) : (
            <p style={{ color: "var(--text-secondary)" }}>No correlated events recorded.</p>
          )}
        </div>

        <div className="detail-section">
          <h4>Metadata</h4>
          <table className="nested-table">
            <tbody>
              <tr><td><strong>Assigned To</strong></td><td>{inc.assigned_to || "–"}</td></tr>
              <tr><td><strong>Created</strong></td><td>{fmtDate(inc.created_at)}</td></tr>
              <tr><td><strong>Updated</strong></td><td>{fmtDate(inc.updated_at)}</td></tr>
              <tr><td><strong>Status</strong></td><td><span className={`badge badge-${inc.status}`}>{inc.status}</span></td></tr>
            </tbody>
          </table>
        </div>

        {inc.notes && (
          <div className="detail-section">
            <h4>Notes</h4>
            <p style={{ whiteSpace: "pre-wrap", margin: 0 }}>{inc.notes}</p>
          </div>
        )}

        <div className="detail-section" style={{ gridColumn: "1 / -1" }}>
          <h4>Raw Incident JSON</h4>
          <JsonView data={inc} initialExpanded={false} />
        </div>
      </div>
    </div>
  );
}

function EvidenceEventRow({
  eventId, isExpanded, onToggle,
}: { eventId: string; isExpanded: boolean; onToggle: () => void }) {
  return (
    <>
      <tr className="clickable-row" onClick={onToggle}>
        <td className="expand-arrow">{isExpanded ? "▼" : "▶"}</td>
        <td style={{ fontFamily: "monospace", fontSize: "0.85rem" }}>{eventId}</td>
      </tr>
      {isExpanded && (
        <tr className="expanded-row">
          <td colSpan={2}><EventDetailPanel eventId={eventId} /></td>
        </tr>
      )}
    </>
  );
}

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
    : data.event_type === "audit" ? "Audit Log" : "Activity Log";

  const scalarEntries = Object.entries(evt).filter(([, v]) => v != null && v !== "" && typeof v !== "object");
  const objectEntries = Object.entries(evt).filter(([, v]) => v != null && typeof v === "object");

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

function renderSimpleMarkdown(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
}
