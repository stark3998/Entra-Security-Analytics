import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchActivityLogs, type ActivityLog, type PaginatedResponse } from "../api";
import SyncStatusPanel from "../components/SyncStatusPanel";
import SortableTable, { type ColumnDef } from "../components/SortableTable";

const PAGE_SIZE = 50;

const columns: ColumnDef<ActivityLog>[] = [
  {
    key: "creation_time",
    header: "Time",
    value: (r) => r.creation_time,
    render: (r) => fmtDate(r.creation_time),
  },
  {
    key: "source",
    header: "Source",
    groupable: true,
    value: (r) => r.source,
    render: (r) => (
      <span className={`badge badge-${sourceBadge(r.source)}`}>{r.source}</span>
    ),
  },
  {
    key: "workload",
    header: "Workload",
    groupable: true,
    value: (r) => r.workload,
  },
  {
    key: "operation",
    header: "Operation",
    groupable: true,
    value: (r) => r.operation,
  },
  {
    key: "user_id",
    header: "User",
    groupable: true,
    value: (r) => r.user_id,
  },
  {
    key: "client_ip",
    header: "IP",
    groupable: true,
    value: (r) => r.client_ip,
  },
  {
    key: "result_status",
    header: "Status",
    groupable: true,
    value: (r) => r.result_status || "–",
  },
  {
    key: "object_id",
    header: "Object",
    value: (r) => r.object_id,
    render: (r) => (
      <span title={r.object_id}>{truncate(r.object_id, 40)}</span>
    ),
  },
];

export default function ActivityLogs() {
  const [offset, setOffset] = useState(0);
  const [source, setSource] = useState("");
  const [user, setUser] = useState("");

  const params: Record<string, string> = {
    offset: String(offset),
    limit: String(PAGE_SIZE),
  };
  if (source) params.source = source;
  if (user) params.user = user;

  const { data, isLoading, error } = useQuery<PaginatedResponse<ActivityLog>>({
    queryKey: ["activity-logs", offset, source, user],
    queryFn: () => fetchActivityLogs(params),
  });

  const total = data?.total ?? 0;
  const items = data?.items ?? [];

  return (
    <div>
      <div className="page-header-row">
        <h1 className="page-heading">Activity Timeline</h1>
        <p className="page-subtitle">Unified timeline of all collected cloud activity across log sources</p>
        <SyncStatusPanel invalidateKeys={[["activity-logs"]]} />
      </div>

      <div className="filters">
        <select value={source} onChange={(e) => { setSource(e.target.value); setOffset(0); }}>
          <option value="">All Sources</option>
          <option value="office365">Office 365</option>
          <option value="sharepoint">SharePoint</option>
          <option value="powerapps">Power Apps</option>
        </select>
        <input
          placeholder="Filter by user…"
          value={user}
          onChange={(e) => { setUser(e.target.value); setOffset(0); }}
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
            defaultSort={{ key: "creation_time", dir: "desc" }}
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

function truncate(s: string, max: number): string {
  if (!s) return "–";
  return s.length > max ? s.slice(0, max) + "…" : s;
}

function sourceBadge(src: string): string {
  if (src === "office365") return "info";
  if (src === "sharepoint") return "medium";
  if (src === "powerapps") return "low";
  return "info";
}
