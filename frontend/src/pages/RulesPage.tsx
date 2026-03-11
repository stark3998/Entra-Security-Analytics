import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { fetchRules, patchRule, deleteRule, type RuleEntry, type PaginatedResponse } from "../api";

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

  return (
    <div>
      <h1 className="page-heading">Correlation Rules</h1>

      {error && <div className="error-box">{String(error)}</div>}

      <div className="card">
        {isLoading ? (
          <p className="loading">Loading…</p>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Slug</th>
                  <th>Name</th>
                  <th>Severity</th>
                  <th>Risk Pts</th>
                  <th>Window (d)</th>
                  <th>Type</th>
                  <th>Enabled</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((rule) => (
                  <tr key={rule.id}>
                    <td className="mono">{rule.slug}</td>
                    <td>{rule.name}</td>
                    <td><span className={`badge badge-${rule.severity}`}>{rule.severity}</span></td>
                    <td>{rule.risk_points}</td>
                    <td>{rule.watch_window_days ?? "–"}</td>
                    <td>{rule.is_system ? <span className="badge badge-system" title="System rule">🔒 System</span> : "Custom"}</td>
                    <td>
                      <label className="toggle">
                        <input
                          type="checkbox"
                          checked={rule.enabled}
                          onChange={() =>
                            toggleMutation.mutate({ id: rule.id, enabled: !rule.enabled })
                          }
                          disabled={toggleMutation.isPending}
                        />
                        <span className="slider" />
                      </label>
                    </td>
                    <td>
                      {!rule.is_system && (
                        <button
                          className="btn btn-sm btn-danger"
                          onClick={() => {
                            if (confirm(`Delete rule "${rule.name}"?`)) {
                              deleteMutation.mutate(rule.id);
                            }
                          }}
                          disabled={deleteMutation.isPending}
                        >
                          Delete
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
