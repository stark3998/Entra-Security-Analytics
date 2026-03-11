import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { fetchIncidents, patchIncident, type IncidentEntry, type PaginatedResponse } from "../api";

const PAGE_SIZE = 50;
const STATUS_OPTIONS = ["", "open", "investigating", "resolved", "closed", "false_positive"];

export default function Incidents() {
  const [offset, setOffset] = useState(0);
  const [statusFilter, setStatusFilter] = useState("");
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

  return (
    <div>
      <h1 className="page-heading">Incidents</h1>

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
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Created</th>
                  <th>Severity</th>
                  <th>Rule</th>
                  <th>User</th>
                  <th>Status</th>
                  <th>MITRE</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((inc) => (
                  <tr key={inc.id}>
                    <td>{inc.id}</td>
                    <td>{fmtDate(inc.created_at)}</td>
                    <td><span className={`badge badge-${inc.severity}`}>{inc.severity}</span></td>
                    <td title={inc.rule_slug}>{inc.rule_name || inc.rule_slug}</td>
                    <td>{inc.user_display_name || inc.user_id}</td>
                    <td><span className={`badge badge-${inc.status}`}>{inc.status}</span></td>
                    <td>{inc.mitre_tactic ? `${inc.mitre_tactic} / ${inc.mitre_technique}` : "–"}</td>
                    <td>
                      {inc.status === "open" && (
                        <button
                          className="btn btn-sm btn-primary"
                          onClick={() => resolveMutation.mutate(inc.id)}
                          disabled={resolveMutation.isPending}
                        >
                          Resolve
                        </button>
                      )}
                    </td>
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
