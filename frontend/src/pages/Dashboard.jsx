/**
 * Dashboard.jsx - findings across every project, in one searchable view.
 * Complements (doesn't replace) each project's own Findings section -
 * this is for "what's the highest-severity thing across everything I'm
 * running right now" without clicking into each project one at a time.
 */

import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { SeverityBadge } from "../components/FindingsList";

const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info", "unknown"];

export function Dashboard() {
  const [findings, setFindings] = useState(null);
  const [error, setError] = useState(null);
  const [severity, setSeverity] = useState("all");
  const [search, setSearch] = useState("");

  useEffect(() => {
    setFindings(null);
    const filters = {};
    if (severity !== "all") filters.severity = severity;
    if (search.trim()) filters.q = search.trim();

    // Debounce the free-text search a little so every keystroke doesn't
    // fire a request - severity changes go through immediately.
    const handle = setTimeout(() => {
      api
        .listAllFindings(filters)
        .then(setFindings)
        .catch((err) => setError(err.message));
    }, search ? 300 : 0);

    return () => clearTimeout(handle);
  }, [severity, search]);

  const tools = useMemo(
    () => (findings ? Array.from(new Set(findings.map((f) => f.tool_name))).sort() : []),
    [findings]
  );

  if (error) {
    return <p style={{ color: "var(--status-fail)" }}>Couldn't load findings: {error}</p>;
  }

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 600, margin: 0 }}>Dashboard</h1>
        <Link to="/" style={{ fontSize: 13, color: "var(--text-secondary)" }}>
          View projects →
        </Link>
      </div>

      <div style={{ display: "flex", gap: 8, marginBottom: 20, flexWrap: "wrap" }}>
        <input
          type="text"
          placeholder="Search evidence across all projects…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ ...inputStyle, flex: 1, minWidth: 200 }}
        />
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} style={inputStyle}>
          <option value="all">All severities</option>
          {SEVERITY_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {s[0].toUpperCase() + s.slice(1)}
            </option>
          ))}
        </select>
      </div>

      {findings === null ? (
        <p style={{ color: "var(--text-muted)" }}>Loading…</p>
      ) : findings.length === 0 ? (
        <div style={{ padding: "48px 16px", textAlign: "center", color: "var(--text-muted)" }}>
          No findings match this search.
        </div>
      ) : (
        <div style={{ border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", overflow: "hidden" }}>
          {findings.map((f, i) => (
            <div
              key={f.id}
              style={{
                display: "flex",
                gap: 16,
                alignItems: "flex-start",
                padding: "12px 16px",
                borderBottom: i < findings.length - 1 ? "1px solid var(--border)" : "none",
              }}
            >
              <div style={{ minWidth: 76 }}>
                <SeverityBadge severity={f.severity} />
              </div>
              <div style={{ minWidth: 130 }}>
                <Link to={`/projects/${f.project_id}`} style={{ fontSize: 13, fontWeight: 500 }}>
                  {f.project_name}
                </Link>
                <div className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>
                  {f.tool_name}
                </div>
              </div>
              <pre
                className="mono"
                style={{
                  flex: 1,
                  minWidth: 0,
                  margin: 0,
                  fontSize: 12,
                  color: "var(--text-secondary)",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                  maxHeight: 40,
                  overflow: "hidden",
                }}
              >
                {f.evidence}
              </pre>
            </div>
          ))}
        </div>
      )}

      {findings && tools.length > 0 && (
        <p style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 12 }}>
          {findings.length} finding{findings.length === 1 ? "" : "s"} across {tools.length} tool{tools.length === 1 ? "" : "s"}
        </p>
      )}
    </div>
  );
}

const inputStyle = {
  background: "var(--bg-surface-raised)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
  color: "var(--text-primary)",
  padding: "8px 12px",
  fontSize: 13,
  fontFamily: "var(--font-ui)",
};
