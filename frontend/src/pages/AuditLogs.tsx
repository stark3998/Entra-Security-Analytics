import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchAuditLogs, type AuditLogEntry, type PaginatedResponse } from "../api";
import SyncStatusPanel from "../components/SyncStatusPanel";
import SortableTable, { type ColumnDef } from "../components/SortableTable";

const PAGE_SIZE = 50;

const columns: ColumnDef<AuditLogEntry>[] = [
  {
    key: "activity_datetime",
    header: "Time",
    value: (r) => r.activity_datetime,
    render: (r) => fmtDate(r.activity_datetime),
  },
  {
    key: "category",
    header: "Category",
    groupable: true,
    value: (r) => r.category,
  },
  {
    key: "activity_display_name",
    header: "Activity",
    groupable: true,
    value: (r) => r.activity_display_name,
  },
  {
    key: "result",
    header: "Result",
    groupable: true,
    value: (r) => r.result,
  },
  {
    key: "initiated_by_user",
    header: "Initiated By (User)",
    groupable: true,
    value: (r) => r.initiated_by_user,
  },
  {
    key: "initiated_by_app",
    header: "Initiated By (App)",
    groupable: true,
    value: (r) => r.initiated_by_app,
  },
  {
    key: "targets",
    header: "Targets",
    sortable: false,
    value: (r) => summarizeTargets(r.target_resources),
    render: (r) => summarizeTargets(r.target_resources),
  },
];

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
        <h1 className="page-heading">Directory Audit Logs</h1>
        <p className="page-subtitle">Entra ID directory changes — role updates, app registrations, and policy modifications</p>
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
          <SortableTable
            columns={columns}
            data={items}
            rowKey={(r) => r.id}
            defaultSort={{ key: "activity_datetime", dir: "desc" }}
          />
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
