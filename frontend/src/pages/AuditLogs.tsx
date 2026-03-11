import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchAuditLogs, type AuditLogEntry, type PaginatedResponse } from "../api";
import SyncStatusPanel from "../components/SyncStatusPanel";

const PAGE_SIZE = 50;

export default function AuditLogs() {
  const [offset, setOffset] = useState(0);
  const [category, setCategory] = useState("");
  const [activity, setActivity] = useState("");

  const params: Record<string, string> = {
    offset: String(offset),
    limit: String(PAGE_SIZE),
  };
  if (category) params.category = category;
  if (activity) params.activity = activity;

  const { data, isLoading, error } = useQuery<PaginatedResponse<AuditLogEntry>>({
    queryKey: ["audit-logs", offset, category, activity],
    queryFn: () => fetchAuditLogs(params),
  });

  const total = data?.total ?? 0;
  const items = data?.items ?? [];

  return (
    <div>
      <div className="page-header-row">
        <h1 className="page-heading">Audit Logs</h1>
        <SyncStatusPanel invalidateKeys={[["audit-logs"]]} />
      </div>

      <div className="filters">
        <input
          placeholder="Filter by category…"
          value={category}
          onChange={(e) => { setCategory(e.target.value); setOffset(0); }}
        />
        <input
          placeholder="Filter by activity…"
          value={activity}
          onChange={(e) => { setActivity(e.target.value); setOffset(0); }}
        />
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
                  <th>Category</th>
                  <th>Activity</th>
                  <th>Result</th>
                  <th>Initiated By (User)</th>
                  <th>Initiated By (App)</th>
                  <th>Targets</th>
                </tr>
              </thead>
              <tbody>
                {items.map((r) => (
                  <tr key={r.id}>
                    <td>{fmtDate(r.activity_datetime)}</td>
                    <td>{r.category}</td>
                    <td>{r.activity_display_name}</td>
                    <td>{r.result}</td>
                    <td>{r.initiated_by_user}</td>
                    <td>{r.initiated_by_app}</td>
                    <td>{summarizeTargets(r.target_resources)}</td>
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

function summarizeTargets(targets: unknown[]): string {
  if (!Array.isArray(targets) || targets.length === 0) return "–";
  return targets
    .slice(0, 2)
    .map((t: any) => t?.displayName || t?.id || "?")
    .join(", ");
}
