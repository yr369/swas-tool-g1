/**
 * FindingsList.jsx - displays scan findings, color-coded by severity,
 * with inline actions: triage (AI severity + VRT category), readiness
 * check (pre-submission pitfalls), and outcome logging (the actual
 * learning-loop input once you get a real Bugcrowd/HackerOne result).
 *
 * Also owns the filter/sort/search bar and the severity distribution
 * chart above the list - both computed client-side from the findings
 * already loaded by ProjectDetail, no extra API calls needed.
 */

import { useMemo, useState } from "react";
import { api } from "../api/client";
import { Donut } from "./charts/Donut";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"];

const SEVERITY_LABEL = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
  unknown: "Unknown",
};

const SORT_OPTIONS = [
  { value: "severity", label: "Severity" },
  { value: "newest", label: "Newest first" },
  { value: "tool", label: "Tool" },
];

const OUTCOME_OPTIONS = [
  { value: "accepted", label: "Accepted" },
  { value: "duplicate", label: "Duplicate" },
  { value: "rejected", label: "Rejected" },
  { value: "informative", label: "Informative" },
  { value: "false_positive", label: "False positive" },
  { value: "not_applicable", label: "Not applicable" },
  { value: "no_response", label: "No response yet" },
];

export function SeverityBadge({ severity }) {
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

// The scope-risk tag - the actual point of Batch 5. triage.py already
// flags categories most programs auto-close (DoS, self-XSS, rate-limit,
// unauthenticated cache purge, etc.) as likely "informative" or
// "out_of_scope" BEFORE you spend time writing a report - this makes
// that judgment visible at findings-view time instead of buried in an
// API response nobody's looking at.
const OUTCOME_TAG = {
  accepted: { color: "var(--status-success)", label: "Likely accepted" },
  informative: { color: "var(--sev-medium)", label: "Likely informative" },
  out_of_scope: { color: "var(--status-fail)", label: "Likely out of scope" },
  duplicate: { color: "var(--text-muted)", label: "Likely duplicate" },
};

export function OutcomeTag({ outcome }) {
  const tag = OUTCOME_TAG[outcome];
  if (!tag) return null;
  return (
    <span
      className="mono"
      style={{
        display: "inline-block",
        fontSize: 11,
        padding: "2px 7px",
        borderRadius: "var(--radius)",
        color: tag.color,
        border: `1px solid ${tag.color}`,
        whiteSpace: "nowrap",
      }}
    >
      {tag.label}
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

function FindingRow({ finding, onTriaged, selected, onToggleSelect }) {
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
    <div style={{ borderBottom: "1px solid var(--border)", opacity: finding.status === "dismissed" ? 0.5 : 1 }}>
      <div
        style={{ display: "flex", gap: 16, padding: "12px 16px", alignItems: "flex-start", cursor: "pointer" }}
        onClick={() => setExpanded((e) => !e)}
      >
        <input
          type="checkbox"
          checked={selected}
          onChange={() => onToggleSelect(finding.id)}
          onClick={(e) => e.stopPropagation()}
          style={{ marginTop: 2 }}
        />
        <div style={{ minWidth: 76 }}>
          <SeverityBadge severity={finding.severity} />
        </div>
        <div style={{ minWidth: 90, color: "var(--text-secondary)" }} className="mono">
          {finding.tool_name}
        </div>
        {finding.likely_program_outcome && (
          <div style={{ minWidth: 0 }}>
            <OutcomeTag outcome={finding.likely_program_outcome} />
          </div>
        )}
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
        {finding.status === "submitted" && !finding.has_logged_outcome && (
          <span
            className="mono"
            style={{ fontSize: 11, color: "var(--signal)", whiteSpace: "nowrap" }}
            title="Submitted but no real-world outcome logged yet - log it once the program responds so future triage can learn from it"
          >
            ⏳ awaiting outcome
          </span>
        )}
        {finding.status !== "new" && (
          <span className="mono" style={{ fontSize: 11, color: "var(--text-muted)", whiteSpace: "nowrap" }}>
            {finding.status}
          </span>
        )}
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

          {triageResult ? (
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
          ) : (
            finding.triage_reasoning && (
              <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 8 }}>
                {finding.likely_program_outcome && (
                  <div>
                    <strong style={{ color: "var(--text-primary)" }}>Likely outcome:</strong>{" "}
                    <OutcomeTag outcome={finding.likely_program_outcome} />
                  </div>
                )}
                <div>
                  <strong style={{ color: "var(--text-primary)" }}>Reasoning:</strong> {finding.triage_reasoning}
                  {finding.triage_confidence != null && ` (${(finding.triage_confidence * 100).toFixed(0)}% confidence)`}
                </div>
              </div>
            )
          )}

          <ReadinessSummary readiness={readiness} />

          {error && <p style={{ color: "var(--status-fail)", fontSize: 12, marginTop: 6 }}>{error}</p>}

          <OutcomeLogger finding={finding} signature={signature} />
        </div>
      )}
    </div>
  );
}

function SeverityChip({ severity, count, active, onToggle }) {
  const color = severity === "unknown" ? "var(--text-muted)" : `var(--sev-${severity})`;
  return (
    <button
      className="chip"
      data-active={active}
      onClick={() => onToggle(severity)}
      style={{ color, borderColor: active ? color : "var(--border)" }}
      type="button"
    >
      {SEVERITY_LABEL[severity]}
      <span className="mono" style={{ color: "var(--text-muted)" }}>
        {count}
      </span>
    </button>
  );
}

export function FindingsList({ findings, onTriaged }) {
  const [activeSeverities, setActiveSeverities] = useState(() => new Set(SEVERITY_ORDER));
  const [toolFilter, setToolFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState("severity");
  const [selected, setSelected] = useState(() => new Set());
  const [bulkUpdating, setBulkUpdating] = useState(false);
  const [onlyAwaitingOutcome, setOnlyAwaitingOutcome] = useState(false);

  const awaitingOutcomeCount = useMemo(
    () => findings.filter((f) => f.status === "submitted" && !f.has_logged_outcome).length,
    [findings]
  );

  const counts = useMemo(() => {
    const c = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]));
    for (const f of findings) {
      const sev = f.severity in c ? f.severity : "unknown";
      c[sev] += 1;
    }
    return c;
  }, [findings]);

  const tools = useMemo(
    () => Array.from(new Set(findings.map((f) => f.tool_name))).sort(),
    [findings]
  );

  function toggleSeverity(sev) {
    setActiveSeverities((prev) => {
      const next = new Set(prev);
      if (next.has(sev)) next.delete(sev);
      else next.add(sev);
      return next;
    });
  }

  function toggleSelect(id) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function handleBulkStatus(status) {
    setBulkUpdating(true);
    try {
      await api.bulkUpdateFindingStatus([...selected], status);
      setSelected(new Set());
      onTriaged?.();
    } catch (err) {
      alert(err.message); // eslint-disable-line no-alert -- simple enough not to need a toast system
    } finally {
      setBulkUpdating(false);
    }
  }

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    let list = findings.filter((f) => {
      const sev = f.severity in counts ? f.severity : "unknown";
      if (!activeSeverities.has(sev)) return false;
      if (toolFilter !== "all" && f.tool_name !== toolFilter) return false;
      if (onlyAwaitingOutcome && !(f.status === "submitted" && !f.has_logged_outcome)) return false;
      if (q && !(f.evidence || "").toLowerCase().includes(q) && !(f.vuln_type || "").toLowerCase().includes(q)) {
        return false;
      }
      return true;
    });

    list = [...list].sort((a, b) => {
      if (sortBy === "severity") {
        return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
      }
      if (sortBy === "tool") {
        return a.tool_name.localeCompare(b.tool_name);
      }
      // newest
      return new Date(b.created_at) - new Date(a.created_at);
    });

    return list;
  }, [findings, activeSeverities, toolFilter, search, sortBy, counts, onlyAwaitingOutcome]);

  if (findings.length === 0) {
    return (
      <div style={{ padding: "32px 16px", textAlign: "center", color: "var(--text-muted)" }}>
        No findings yet. Run a scan to see results here.
      </div>
    );
  }

  const donutSegments = SEVERITY_ORDER.filter((s) => s !== "unknown" || counts.unknown > 0).map((s) => ({
    key: s,
    label: SEVERITY_LABEL[s],
    value: counts[s],
    color: s === "unknown" ? "var(--text-muted)" : `var(--sev-${s})`,
  }));

  return (
    <div>
      {awaitingOutcomeCount > 0 && (
        <div
          style={{
            display: "flex", alignItems: "center", gap: 10, padding: "8px 12px", marginBottom: 12,
            background: "var(--signal-dim)", border: "1px solid var(--signal)", borderRadius: "var(--radius)",
            fontSize: 12, color: "var(--signal)",
          }}
        >
          <span>
            ⏳ {awaitingOutcomeCount} submitted finding{awaitingOutcomeCount === 1 ? "" : "s"} with no outcome logged
            yet - logging real results is what lets future triage learn from past submissions.
          </span>
          <button
            onClick={() => setOnlyAwaitingOutcome((v) => !v)}
            style={{ ...smallButtonStyle, color: "var(--signal)", borderColor: "var(--signal)", marginLeft: "auto" }}
          >
            {onlyAwaitingOutcome ? "Show all" : "Show these"}
          </button>
        </div>
      )}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: 24,
          padding: "16px 4px 20px",
        }}
      >
        <Donut segments={donutSegments} />

        <div style={{ display: "flex", flexDirection: "column", gap: 10, alignItems: "flex-end" }}>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", justifyContent: "flex-end" }}>
            {SEVERITY_ORDER.filter((s) => counts[s] > 0).map((s) => (
              <SeverityChip
                key={s}
                severity={s}
                count={counts[s]}
                active={activeSeverities.has(s)}
                onToggle={toggleSeverity}
              />
            ))}
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <input
              type="text"
              placeholder="Search evidence…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{ ...filterInputStyle, width: 160 }}
            />
            <select value={toolFilter} onChange={(e) => setToolFilter(e.target.value)} style={filterInputStyle}>
              <option value="all">All tools</option>
              {tools.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
            <select value={sortBy} onChange={(e) => setSortBy(e.target.value)} style={filterInputStyle}>
              {SORT_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  Sort: {o.label}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {selected.size > 0 && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: "8px 12px",
            marginBottom: 10,
            background: "var(--bg-surface-raised)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius)",
          }}
        >
          <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>{selected.size} selected</span>
          <button onClick={() => handleBulkStatus("reviewed")} disabled={bulkUpdating} style={smallButtonStyle}>
            Mark reviewed
          </button>
          <button onClick={() => handleBulkStatus("submitted")} disabled={bulkUpdating} style={smallButtonStyle}>
            Mark submitted
          </button>
          <button
            onClick={() => handleBulkStatus("dismissed")}
            disabled={bulkUpdating}
            style={{ ...smallButtonStyle, color: "var(--text-muted)" }}
          >
            Dismiss
          </button>
          <button onClick={() => setSelected(new Set())} style={{ ...smallButtonStyle, marginLeft: "auto" }}>
            Clear
          </button>
        </div>
      )}

      {visible.length === 0 ? (
        <div style={{ padding: "32px 16px", textAlign: "center", color: "var(--text-muted)", border: "1px solid var(--border)", borderRadius: "var(--radius-lg)" }}>
          No findings match these filters.
        </div>
      ) : (
        <div style={{ border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", overflow: "hidden" }}>
          {visible.map((finding) => (
            <FindingRow
              key={finding.id}
              finding={finding}
              onTriaged={onTriaged}
              selected={selected.has(finding.id)}
              onToggleSelect={toggleSelect}
            />
          ))}
        </div>
      )}
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

const filterInputStyle = {
  background: "var(--bg-surface-raised)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
  color: "var(--text-primary)",
  padding: "6px 10px",
  fontSize: 12,
  fontFamily: "var(--font-ui)",
};
