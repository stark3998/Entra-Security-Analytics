import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { fetchRules, patchRule, deleteRule, type RuleEntry, type PaginatedResponse } from "../api";
import SortableTable, { type ColumnDef } from "../components/SortableTable";

const PAGE_SIZE = 50;

export default function RulesPage() {
  const [offset, setOffset] = useState(0);
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
      key: "slug",
      header: "Slug",
      value: (r) => r.slug,
      className: "mono",
    },
    {
      key: "name",
      header: "Name",
      value: (r) => r.name,
    },
    {
      key: "severity",
      header: "Severity",
      groupable: true,
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
      header: "Actions",
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
            defaultSort={{ key: "name", dir: "asc" }}
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
