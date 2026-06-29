/**
 * FindingsList.jsx - displays scan findings, color-coded by severity.
 *
 * Severity colors come straight from the design tokens (--sev-*) and
 * encode real meaning, not decoration - critical is genuinely more
 * urgent than info, and the color should make that legible at a glance.
 */

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"];

const SEVERITY_LABEL = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
  unknown: "Unknown",
};

function SeverityBadge({ severity }) {
  const sev = severity in SEVERITY_LABEL ? severity : "unknown";
  const color = sev === "unknown" ? "var(--text-muted)" : `var(--sev-${sev})`;
  const bg = sev === "unknown" ? "var(--bg-surface-raised)" : `var(--sev-${sev}-bg)`;

  return (
    <span
      style={{
        display: "inline-block",
        fontSize: 12,
        fontWeight: 500,
        padding: "2px 8px",
        borderRadius: "var(--radius)",
        color,
        background: bg,
        whiteSpace: "nowrap",
      }}
    >
      {SEVERITY_LABEL[sev]}
    </span>
  );
}

function FindingRow({ finding }) {
  return (
    <div
      style={{
        display: "flex",
        gap: 16,
        padding: "12px 16px",
        borderBottom: "1px solid var(--border)",
        alignItems: "flex-start",
      }}
    >
      <div style={{ minWidth: 76 }}>
        <SeverityBadge severity={finding.severity} />
      </div>
      <div style={{ minWidth: 90, color: "var(--text-secondary)" }} className="mono">
        {finding.tool_name}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <pre
          className="mono"
          style={{
            margin: 0,
            fontSize: 12,
            color: "var(--text-secondary)",
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
            maxHeight: 120,
            overflowY: "auto",
          }}
        >
          {finding.evidence}
        </pre>
      </div>
    </div>
  );
}

export function FindingsList({ findings }) {
  if (findings.length === 0) {
    return (
      <div style={{ padding: "32px 16px", textAlign: "center", color: "var(--text-muted)" }}>
        No findings yet. Run a scan to see results here.
      </div>
    );
  }

  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", overflow: "hidden" }}>
      {sorted.map((finding) => (
        <FindingRow key={finding.id} finding={finding} />
      ))}
    </div>
  );
}
