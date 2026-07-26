/**
 * TriageQueue.jsx - the cross-project triage inbox. Recon/scan/verify
 * already runs unattended; the operator's actual bottleneck is working
 * through what those phases produced. This pools findings from every
 * project into one queue, sorted by how UNSURE the AI triage step was
 * (lowest confidence first) by default - that's where a human's time
 * is worth the most, not re-reading the ones the model was already
 * confident about.
 *
 * Fully keyboard-operable: j/k to move, a/r/s to decide, no mouse
 * required for a full triage pass.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { SeverityBadge, OutcomeTag } from "../components/FindingsList";
import { platformLabel } from "../constants";

const SORTS = [
  { value: "confidence", label: "Least confident first" },
  { value: "severity", label: "Severity" },
  { value: "recent", label: "Newest first" },
];

function formatDate(isoString) {
  const date = new Date(isoString);
  return (
    date.toLocaleDateString(undefined, { month: "short", day: "numeric" }) +
    " " +
    date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
  );
}

export function TriageQueue() {
  const [findings, setFindings] = useState(null);
  const [error, setError] = useState(null);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [includeReviewed, setIncludeReviewed] = useState(false);
  const [sort, setSort] = useState("confidence");
  const [actingId, setActingId] = useState(null);
  const [lastAction, setLastAction] = useState(null);

  const load = useCallback(() => {
    const status = includeReviewed ? "new,reviewed" : "new";
    return api
      .listAllFindings({ status, sort, limit: 500 })
      .then((data) => {
        setFindings(data);
        setSelectedIndex((i) => Math.min(i, Math.max(data.length - 1, 0)));
      })
      .catch((err) => setError(err.message));
  }, [includeReviewed, sort]);

  useEffect(() => {
    load();
  }, [load]);

  const current = findings && findings.length > 0 ? findings[selectedIndex] : null;

  const decide = useCallback(
    async (status) => {
      if (!current || actingId) return;
      setActingId(current.id);
      try {
        await api.bulkUpdateFindingStatus([current.id], status);
        setLastAction({ vulnType: current.vuln_type, status });
        setFindings((prev) => {
          const next = prev.filter((f) => f.id !== current.id);
          setSelectedIndex((i) => Math.min(i, Math.max(next.length - 1, 0)));
          return next;
        });
      } catch (err) {
        setError(err.message);
      } finally {
        setActingId(null);
      }
    },
    [current, actingId]
  );

  useEffect(() => {
    function onKeyDown(e) {
      const el = e.target;
      if (el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.isContentEditable)) return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;

      if (!findings || findings.length === 0) return;

      switch (e.key.toLowerCase()) {
        case "j":
        case "arrowdown":
          e.preventDefault();
          setSelectedIndex((i) => Math.min(i + 1, findings.length - 1));
          break;
        case "k":
        case "arrowup":
          e.preventDefault();
          setSelectedIndex((i) => Math.max(i - 1, 0));
          break;
        case "a":
          e.preventDefault();
          decide("reviewed");
          break;
        case "r":
          e.preventDefault();
          decide("dismissed");
          break;
        case "s":
          e.preventDefault();
          decide("submitted");
          break;
        default:
          break;
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [findings, decide]);

  const counts = useMemo(() => {
    if (!findings) return null;
    return findings.reduce(
      (acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
      },
      {}
    );
  }, [findings]);

  if (error) return <p style={{ color: "var(--status-fail)" }}>Couldn't load queue: {error}</p>;
  if (findings === null) return <p style={{ color: "var(--text-muted)" }}>Loading…</p>;

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: 14, flexWrap: "wrap", gap: 10 }}>
        <div>
          <div className="eyebrow" style={{ marginBottom: 4 }}>Cross-project inbox</div>
          <h1 style={{ fontSize: 24, fontWeight: 500, margin: 0 }}>Triage queue</h1>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <select value={sort} onChange={(e) => setSort(e.target.value)} className="input" style={{ fontSize: 12, padding: "6px 10px" }}>
            {SORTS.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </select>
          <button
            className="chip"
            data-active={includeReviewed}
            onClick={() => setIncludeReviewed((v) => !v)}
          >
            + Reviewed
          </button>
        </div>
      </div>

      {findings.length === 0 ? (
        <div className="ops-panel" style={{ padding: "48px 16px", textAlign: "center", color: "var(--text-muted)" }}>
          Queue's empty. Nothing new needs a decision right now.
          {lastAction && (
            <div style={{ marginTop: 8, fontSize: 12, color: "var(--status-success)" }}>
              Last: "{lastAction.vulnType}" → {lastAction.status}
            </div>
          )}
        </div>
      ) : (
        <div style={{ display: "flex", gap: 16, flex: 1, minHeight: 0 }}>
          <div
            className="ops-panel"
            data-label={`QUEUE · ${findings.length}`}
            style={{ width: 340, flexShrink: 0, overflowY: "auto", padding: "12px 10px" }}
          >
            {findings.map((f, i) => (
              <button
                key={f.id}
                onClick={() => setSelectedIndex(i)}
                style={{
                  display: "block",
                  width: "100%",
                  textAlign: "left",
                  padding: "9px 10px",
                  marginBottom: 4,
                  background: i === selectedIndex ? "var(--accent-dim)" : "transparent",
                  border: "none",
                  borderLeft: i === selectedIndex ? "2px solid var(--accent)" : "2px solid transparent",
                  borderRadius: "var(--radius)",
                  cursor: "pointer",
                  color: "var(--text-primary)",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 6 }}>
                  <span style={{ fontSize: 13, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {f.vuln_type}
                  </span>
                  <SeverityBadge severity={f.severity} />
                </div>
                <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 3, display: "flex", justifyContent: "space-between" }}>
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.project_name}</span>
                  {f.triage_confidence != null && <span className="mono">{Math.round(f.triage_confidence * 100)}%</span>}
                </div>
              </button>
            ))}
          </div>

          <div className="ops-panel" style={{ flex: 1, minWidth: 0, overflowY: "auto", padding: "20px 22px" }}>
            {current && (
              <>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12, marginBottom: 10 }}>
                  <div style={{ minWidth: 0 }}>
                    <h2 style={{ fontSize: 18, fontWeight: 500, margin: "0 0 4px" }}>{current.vuln_type}</h2>
                    <Link to={`/projects/${current.project_id}`} style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                      {current.project_name} ({platformLabel(current.project_platform)}) →
                    </Link>
                  </div>
                  <div style={{ display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                    <SeverityBadge severity={current.severity} />
                    {current.likely_program_outcome && <OutcomeTag outcome={current.likely_program_outcome} />}
                  </div>
                </div>

                <div style={{ display: "flex", gap: 14, fontSize: 12, color: "var(--text-muted)", marginBottom: 16, flexWrap: "wrap" }}>
                  <span className="mono">{current.tool_name}</span>
                  <span>{formatDate(current.created_at)}</span>
                  {current.triage_confidence != null && (
                    <span>AI confidence: {Math.round(current.triage_confidence * 100)}%</span>
                  )}
                </div>

                {current.triage_reasoning && (
                  <div style={{ marginBottom: 16, fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.5 }}>
                    {current.triage_reasoning}
                  </div>
                )}

                {current.evidence && (
                  <pre
                    className="mono"
                    style={{
                      background: "var(--bg-canvas)",
                      border: "1px solid var(--border)",
                      borderRadius: "var(--radius)",
                      padding: 14,
                      fontSize: 12,
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-word",
                      maxHeight: 340,
                      overflowY: "auto",
                      marginBottom: 18,
                    }}
                  >
                    {current.evidence}
                  </pre>
                )}

                <div style={{ display: "flex", gap: 8 }}>
                  <button className="btn btn-primary" onClick={() => decide("reviewed")} disabled={actingId === current.id}>
                    Accept <span className="kbd" style={{ marginLeft: 4 }}>A</span>
                  </button>
                  <button className="btn btn-danger" onClick={() => decide("dismissed")} disabled={actingId === current.id}>
                    Reject <span className="kbd" style={{ marginLeft: 4 }}>R</span>
                  </button>
                  <button className="btn" onClick={() => decide("submitted")} disabled={actingId === current.id}>
                    Mark submitted <span className="kbd" style={{ marginLeft: 4 }}>S</span>
                  </button>
                  <Link to={`/report/${current.id}`} className="btn" style={{ textDecoration: "none" }}>
                    Build report
                  </Link>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      <div
        className="mono"
        style={{ display: "flex", gap: 16, fontSize: 11, color: "var(--text-muted)", padding: "10px 4px 0", flexShrink: 0 }}
      >
        {counts &&
          Object.entries(counts).map(([sev, n]) => (
            <span key={sev}>
              {sev}: {n}
            </span>
          ))}
        <span style={{ marginLeft: "auto" }}>
          <span className="kbd">J</span>/<span className="kbd">K</span> navigate ·{" "}
          <span className="kbd">A</span> accept · <span className="kbd">R</span> reject ·{" "}
          <span className="kbd">S</span> submitted
        </span>
      </div>
    </div>
  );
}
