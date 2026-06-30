/**
 * FindingsList.jsx - displays scan findings, color-coded by severity,
 * with inline actions: triage (AI severity + VRT category), readiness
 * check (pre-submission pitfalls), and outcome logging (the actual
 * learning-loop input once you get a real Bugcrowd/HackerOne result).
 */

import { useState } from "react";
import { api } from "../api/client";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"];

const SEVERITY_LABEL = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
  unknown: "Unknown",
};

const OUTCOME_OPTIONS = [
  { value: "accepted", label: "Accepted" },
  { value: "duplicate", label: "Duplicate" },
  { value: "rejected", label: "Rejected" },
  { value: "informative", label: "Informative" },
  { value: "not_applicable", label: "Not applicable" },
  { value: "no_response", label: "No response yet" },
];

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

function ReadinessSummary({ readiness }) {
  if (!readiness) return null;
  const failedChecks = readiness.checks.filter((c) => !c.passed);

  return (
    <div
      style={{
        marginTop: 8,
        padding: "8px 10px",
        borderRadius: "var(--radius)",
        background: readiness.ready ? "var(--bg-surface-raised)" : "var(--sev-medium-bg)",
        fontSize: 12,
      }}
    >
      <div style={{ color: readiness.ready ? "var(--status-success)" : "var(--sev-medium)", fontWeight: 500 }}>
        {readiness.ready ? "✓ Ready to submit" : "Not ready yet"}
      </div>
      {!readiness.ready &&
        failedChecks.map((c) => (
          <div key={c.name} style={{ color: "var(--text-secondary)", marginTop: 4 }}>
            • {c.detail}
          </div>
        ))}
    </div>
  );
}

function OutcomeLogger({ finding, signature, onLogged }) {
  const [outcome, setOutcome] = useState("");
  const [loading, setLoading] = useState(false);
  const [logged, setLogged] = useState(false);

  async function handleLog() {
    if (!outcome) return;
    setLoading(true);
    try {
      await api.logOutcome({ finding_id: finding.id, signature, outcome, platform: "bugcrowd" });
      setLogged(true);
      onLogged?.();
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  if (logged) {
    return <span style={{ fontSize: 12, color: "var(--status-success)" }}>Outcome logged - thanks, this feeds future triage</span>;
  }

  return (
    <div style={{ display: "flex", gap: 6, alignItems: "center", marginTop: 8 }}>
      <select value={outcome} onChange={(e) => setOutcome(e.target.value)} style={selectStyle}>
        <option value="">Log real outcome…</option>
        {OUTCOME_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <button onClick={handleLog} disabled={!outcome || loading} style={smallButtonStyle}>
        {loading ? "…" : "Save"}
      </button>
    </div>
  );
}

function FindingRow({ finding, onTriaged }) {
  const [expanded, setExpanded] = useState(false);
  const [triaging, setTriaging] = useState(false);
  const [triageResult, setTriageResult] = useState(null);
  const [readiness, setReadiness] = useState(null);
  const [checkingReadiness, setCheckingReadiness] = useState(false);
  const [error, setError] = useState(null);

  async function handleTriage() {
    setTriaging(true);
    setError(null);
    try {
      const result = await api.triageFinding(finding.id);
      setTriageResult(result);
      onTriaged?.();
    } catch (err) {
      setError(err.message);
    } finally {
      setTriaging(false);
    }
  }

  async function handleCheckReadiness() {
    setCheckingReadiness(true);
    setError(null);
    try {
      const result = await api.getReadiness(finding.id);
      setReadiness(result);
    } catch (err) {
      setError(err.message);
    } finally {
      setCheckingReadiness(false);
    }
  }

  const signature = triageResult?.signature || `${finding.tool_name}:${finding.vuln_type}:website`;

  return (
    <div style={{ borderBottom: "1px solid var(--border)" }}>
      <div
        style={{ display: "flex", gap: 16, padding: "12px 16px", alignItems: "flex-start", cursor: "pointer" }}
        onClick={() => setExpanded((e) => !e)}
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
              maxHeight: expanded ? "none" : 60,
              overflow: expanded ? "visible" : "hidden",
            }}
          >
            {finding.evidence}
          </pre>
        </div>
      </div>

      {expanded && (
        <div style={{ padding: "0 16px 16px 122px" }} onClick={(e) => e.stopPropagation()}>
          <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
            <button onClick={handleTriage} disabled={triaging} style={smallButtonStyle}>
              {triaging ? "Triaging…" : "Run AI triage"}
            </button>
            <button onClick={handleCheckReadiness} disabled={checkingReadiness} style={smallButtonStyle}>
              {checkingReadiness ? "Checking…" : "Check submission readiness"}
            </button>
          </div>

          {triageResult && (
            <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 8 }}>
              <div>
                <strong style={{ color: "var(--text-primary)" }}>Confidence:</strong>{" "}
                {(triageResult.confidence * 100).toFixed(0)}% ({triageResult.model_used})
              </div>
              <div>
                <strong style={{ color: "var(--text-primary)" }}>Reasoning:</strong> {triageResult.reasoning}
              </div>
              {triageResult.vrt_category && (
                <div>
                  <strong style={{ color: "var(--text-primary)" }}>VRT category:</strong> {triageResult.vrt_category}
                </div>
              )}
            </div>
          )}

          <ReadinessSummary readiness={readiness} />

          {error && <p style={{ color: "var(--status-fail)", fontSize: 12, marginTop: 6 }}>{error}</p>}

          <OutcomeLogger finding={finding} signature={signature} />
        </div>
      )}
    </div>
  );
}

export function FindingsList({ findings, onTriaged }) {
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
        <FindingRow key={finding.id} finding={finding} onTriaged={onTriaged} />
      ))}
    </div>
  );
}

const smallButtonStyle = {
  background: "transparent",
  color: "var(--accent)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
  padding: "5px 10px",
  fontSize: 12,
  cursor: "pointer",
};

const selectStyle = {
  background: "var(--bg-surface-raised)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
  color: "var(--text-primary)",
  padding: "4px 8px",
  fontSize: 12,
};
