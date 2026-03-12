import { useState, useMemo, useCallback, type ReactNode } from "react";

/* ── Column definition ────────────────────────────────────────── */

export interface ColumnDef<T> {
  /** Unique key for the column */
  key: string;
  /** Header label */
  header: string;
  /** Whether this column is sortable (default true) */
  sortable?: boolean;
  /** Whether this column can be grouped by (default false) */
  groupable?: boolean;
  /** Accessor to get the raw value for sorting/grouping */
  value: (row: T) => string | number | boolean | null | undefined;
  /** Custom cell renderer (defaults to String(value)) */
  render?: (row: T) => ReactNode;
  /** Optional className on td */
  className?: string;
}

/* ── Sort state ───────────────────────────────────────────────── */

type SortDir = "asc" | "desc";

interface SortState {
  key: string;
  dir: SortDir;
}

/* ── Props ────────────────────────────────────────────────────── */

interface SortableTableProps<T> {
  columns: ColumnDef<T>[];
  data: T[];
  /** Unique key per row */
  rowKey: (row: T) => string | number;
  /** If provided, renders an expand arrow and calls this on row click */
  expandedKey?: string | number | null;
  onToggleExpand?: (key: string | number) => void;
  /** Render content for expanded row */
  renderExpanded?: (row: T) => ReactNode;
  /** ColSpan for expanded row (auto-calculated if not set) */
  expandColSpan?: number;
  /** Extra columns before data columns (e.g. expand arrow) — handled automatically if expandedKey is set */
  /** Default sort */
  defaultSort?: SortState;
  /** Show group-by selector (default true if any column is groupable) */
  showGroupBy?: boolean;
  /** Extra class on table element */
  className?: string;
}

/* ── Component ────────────────────────────────────────────────── */

export default function SortableTable<T>({
  columns,
  data,
  rowKey,
  expandedKey,
  onToggleExpand,
  renderExpanded,
  expandColSpan,
  defaultSort,
  showGroupBy,
  className,
}: SortableTableProps<T>) {
  const [sort, setSort] = useState<SortState | null>(defaultSort ?? null);
  const [groupByKey, setGroupByKey] = useState<string>("");

  const hasExpand = onToggleExpand != null && renderExpanded != null;
  const totalCols = expandColSpan ?? columns.length + (hasExpand ? 1 : 0);

  const groupableColumns = columns.filter((c) => c.groupable);
  const shouldShowGroupBy = showGroupBy ?? groupableColumns.length > 0;

  // Toggle sort on column header click
  const handleSort = useCallback(
    (key: string) => {
      setSort((prev) => {
        if (prev?.key === key) {
          return prev.dir === "asc" ? { key, dir: "desc" } : null;
        }
        return { key, dir: "asc" };
      });
    },
    []
  );

  // Sort + group data
  const { groups, sortedFlat } = useMemo(() => {
    let items = [...data];

    // Sort
    if (sort) {
      const col = columns.find((c) => c.key === sort.key);
      if (col) {
        items.sort((a, b) => {
          const va = col.value(a);
          const vb = col.value(b);
          return compareValues(va, vb, sort.dir);
        });
      }
    }

    // Group
    if (groupByKey) {
      const col = columns.find((c) => c.key === groupByKey);
      if (col) {
        const map = new Map<string, T[]>();
        for (const row of items) {
          const raw = col.value(row);
          const label = raw == null || raw === "" ? "(empty)" : String(raw);
          if (!map.has(label)) map.set(label, []);
          map.get(label)!.push(row);
        }
        return {
          groups: Array.from(map.entries()).map(([label, rows]) => ({ label, rows })),
          sortedFlat: items,
        };
      }
    }

    return { groups: null, sortedFlat: items };
  }, [data, sort, groupByKey, columns]);

  // Render header cell
  const renderHeader = (col: ColumnDef<T>) => {
    const isSortable = col.sortable !== false;
    const isActive = sort?.key === col.key;

    return (
      <th
        key={col.key}
        className={isSortable ? "sortable-th" : ""}
        onClick={isSortable ? () => handleSort(col.key) : undefined}
        title={isSortable ? `Sort by ${col.header}` : undefined}
      >
        <span className="th-content">
          {col.header}
          {isSortable && (
            <span className={`sort-indicator ${isActive ? "active" : ""}`}>
              {isActive ? (sort!.dir === "asc" ? " ▲" : " ▼") : " ⇅"}
            </span>
          )}
        </span>
      </th>
    );
  };

  // Render a data row (+ optional expanded row)
  const renderRow = (row: T) => {
    const key = rowKey(row);
    const isExpanded = hasExpand && expandedKey === key;

    return (
      <RowPair
        key={key}
        row={row}
        columns={columns}
        hasExpand={hasExpand}
        isExpanded={isExpanded}
        onToggle={hasExpand ? () => onToggleExpand!(key) : undefined}
        renderExpanded={renderExpanded}
        totalCols={totalCols}
      />
    );
  };

  return (
    <div>
      {/* Group-by selector */}
      {shouldShowGroupBy && groupableColumns.length > 0 && (
        <div className="group-by-bar">
          <label className="group-by-label">Group by:</label>
          <select
            className="group-by-select"
            value={groupByKey}
            onChange={(e) => setGroupByKey(e.target.value)}
          >
            <option value="">None</option>
            {groupableColumns.map((c) => (
              <option key={c.key} value={c.key}>
                {c.header}
              </option>
            ))}
          </select>
        </div>
      )}

      <div className="table-wrapper">
        <table className={className}>
          <thead>
            <tr>
              {hasExpand && <th style={{ width: 28 }}></th>}
              {columns.map(renderHeader)}
            </tr>
          </thead>

          {groups ? (
            // Grouped rendering
            groups.map((g) => (
              <tbody key={g.label}>
                <tr className="group-header-row">
                  <td colSpan={totalCols}>
                    <span className="group-label">{groupByKey && columns.find(c => c.key === groupByKey)?.header}: </span>
                    <strong>{g.label}</strong>
                    <span className="group-count">{g.rows.length}</span>
                  </td>
                </tr>
                {g.rows.map(renderRow)}
              </tbody>
            ))
          ) : (
            <tbody>{sortedFlat.map(renderRow)}</tbody>
          )}
        </table>
      </div>
    </div>
  );
}

/* ── Row pair (data row + optional expanded) ──────────────────── */

function RowPair<T>({
  row,
  columns,
  hasExpand,
  isExpanded,
  onToggle,
  renderExpanded,
  totalCols,
}: {
  row: T;
  columns: ColumnDef<T>[];
  hasExpand: boolean;
  isExpanded: boolean;
  onToggle?: () => void;
  renderExpanded?: (row: T) => ReactNode;
  totalCols: number;
}) {
  return (
    <>
      <tr
        className={hasExpand ? "clickable-row" : ""}
        onClick={hasExpand ? onToggle : undefined}
      >
        {hasExpand && (
          <td className="expand-arrow">{isExpanded ? "▼" : "▶"}</td>
        )}
        {columns.map((col) => (
          <td key={col.key} className={col.className}>
            {col.render ? col.render(row) : String(col.value(row) ?? "–")}
          </td>
        ))}
      </tr>
      {isExpanded && renderExpanded && (
        <tr className="expanded-row">
          <td colSpan={totalCols}>{renderExpanded(row)}</td>
        </tr>
      )}
    </>
  );
}

/* ── Comparison helper ────────────────────────────────────────── */

function compareValues(
  a: string | number | boolean | null | undefined,
  b: string | number | boolean | null | undefined,
  dir: SortDir
): number {
  // Nulls sort last
  if (a == null && b == null) return 0;
  if (a == null) return 1;
  if (b == null) return -1;

  let result: number;
  if (typeof a === "number" && typeof b === "number") {
    result = a - b;
  } else if (typeof a === "boolean" && typeof b === "boolean") {
    result = (a ? 1 : 0) - (b ? 1 : 0);
  } else {
    result = String(a).localeCompare(String(b), undefined, {
      sensitivity: "base",
      numeric: true,
    });
  }

  return dir === "desc" ? -result : result;
}
