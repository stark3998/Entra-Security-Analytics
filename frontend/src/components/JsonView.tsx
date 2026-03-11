import { useState } from "react";

/**
 * Renders a JSON value with syntax highlighting, collapsible nested objects,
 * and copy-to-clipboard support.
 */
export default function JsonView({ data, initialExpanded = true }: { data: unknown; initialExpanded?: boolean }) {
  return (
    <div className="json-view">
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: "0.25rem" }}>
        <button
          className="btn btn-sm"
          style={{ fontSize: "0.75rem", padding: "0.15rem 0.5rem" }}
          onClick={() => navigator.clipboard.writeText(JSON.stringify(data, null, 2))}
          title="Copy JSON"
        >
          Copy
        </button>
      </div>
      <pre className="json-pre">
        <JsonNode value={data} depth={0} initialExpanded={initialExpanded} />
      </pre>
    </div>
  );
}

function JsonNode({ value, depth, initialExpanded }: { value: unknown; depth: number; initialExpanded: boolean }) {
  if (value === null) return <span className="json-null">null</span>;
  if (value === undefined) return <span className="json-null">undefined</span>;

  switch (typeof value) {
    case "string":
      return <span className="json-string">"{value}"</span>;
    case "number":
      return <span className="json-number">{value}</span>;
    case "boolean":
      return <span className="json-boolean">{String(value)}</span>;
    case "object":
      if (Array.isArray(value)) {
        return <JsonArray items={value} depth={depth} initialExpanded={initialExpanded} />;
      }
      return <JsonObject obj={value as Record<string, unknown>} depth={depth} initialExpanded={initialExpanded} />;
    default:
      return <span>{String(value)}</span>;
  }
}

function JsonObject({ obj, depth, initialExpanded }: { obj: Record<string, unknown>; depth: number; initialExpanded: boolean }) {
  const [expanded, setExpanded] = useState(depth < 2 && initialExpanded);
  const entries = Object.entries(obj);

  if (entries.length === 0) return <span>{"{}"}</span>;

  const indent = "  ".repeat(depth + 1);
  const closingIndent = "  ".repeat(depth);

  if (!expanded) {
    return (
      <span>
        <span className="json-toggle" onClick={() => setExpanded(true)}>{"{ "}</span>
        <span className="json-collapsed" onClick={() => setExpanded(true)}>
          {entries.length} {entries.length === 1 ? "key" : "keys"}
        </span>
        <span className="json-toggle" onClick={() => setExpanded(true)}>{" }"}</span>
      </span>
    );
  }

  return (
    <span>
      <span className="json-toggle" onClick={() => setExpanded(false)}>{"{"}</span>
      {"\n"}
      {entries.map(([key, val], i) => (
        <span key={key}>
          {indent}
          <span className="json-key">"{key}"</span>
          <span className="json-colon">: </span>
          <JsonNode value={val} depth={depth + 1} initialExpanded={initialExpanded} />
          {i < entries.length - 1 ? "," : ""}
          {"\n"}
        </span>
      ))}
      {closingIndent}
      <span className="json-toggle" onClick={() => setExpanded(false)}>{"}"}</span>
    </span>
  );
}

function JsonArray({ items, depth, initialExpanded }: { items: unknown[]; depth: number; initialExpanded: boolean }) {
  const [expanded, setExpanded] = useState(depth < 2 && initialExpanded);

  if (items.length === 0) return <span>{"[]"}</span>;

  const indent = "  ".repeat(depth + 1);
  const closingIndent = "  ".repeat(depth);

  if (!expanded) {
    return (
      <span>
        <span className="json-toggle" onClick={() => setExpanded(true)}>{"[ "}</span>
        <span className="json-collapsed" onClick={() => setExpanded(true)}>
          {items.length} {items.length === 1 ? "item" : "items"}
        </span>
        <span className="json-toggle" onClick={() => setExpanded(true)}>{" ]"}</span>
      </span>
    );
  }

  return (
    <span>
      <span className="json-toggle" onClick={() => setExpanded(false)}>{"["}</span>
      {"\n"}
      {items.map((item, i) => (
        <span key={i}>
          {indent}
          <JsonNode value={item} depth={depth + 1} initialExpanded={initialExpanded} />
          {i < items.length - 1 ? "," : ""}
          {"\n"}
        </span>
      ))}
      {closingIndent}
      <span className="json-toggle" onClick={() => setExpanded(false)}>{"]"}</span>
    </span>
  );
}
