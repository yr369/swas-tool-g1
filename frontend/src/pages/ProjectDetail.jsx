import { useCallback, useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../api/client";
import { PipelineTracker } from "../components/PipelineTracker";
import { FindingsList } from "../components/FindingsList";

// While a scan is running, poll for updates. This interval is deliberately
// not aggressive - the backend's phases genuinely take minutes (we saw
// nuclei alone take ~4 min in real testing), so there's no benefit to
// polling faster than this.
const POLL_INTERVAL_MS = 5000;

export function ProjectDetail() {
  const { id } = useParams();
  const [project, setProject] = useState(null);
  const [scope, setScope] = useState([]);
  const [phaseRuns, setPhaseRuns] = useState([]);
  const [findings, setFindings] = useState([]);
  const [scanStarting, setScanStarting] = useState(false);
  const [triagingAll, setTriagingAll] = useState(false);
  const [error, setError] = useState(null);
  const pollRef = useRef(null);

  const loadAll = useCallback(async () => {
    try {
      const [proj, scopeList, runs, findingsList] = await Promise.all([
        api.getProject(id),
        api.listScope(id),
        api.listPhaseRuns(id),
        api.listFindings(id),
      ]);
      setProject(proj);
      setScope(scopeList);
      setPhaseRuns(runs);
      setFindings(findingsList);
    } catch (err) {
      setError(err.message);
    }
  }, [id]);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

  // Poll only while something looks like it's actively running - no point
  // hammering the API once everything's settled into a final state.
  useEffect(() => {
    const isActive = phaseRuns.some((r) => r.status === "in_progress" || r.status === "pending");
    if (isActive) {
      pollRef.current = setInterval(loadAll, POLL_INTERVAL_MS);
      return () => clearInterval(pollRef.current);
    }
  }, [phaseRuns, loadAll]);

  async function handleStartScan() {
    setScanStarting(true);
    setError(null);
    try {
      await api.startScan(id);
      await loadAll();
    } catch (err) {
      setError(err.message);
    } finally {
      setScanStarting(false);
    }
  }

  async function handleTriageAll() {
    setTriagingAll(true);
    setError(null);
    try {
      await api.triageAll(id);
      await loadAll();
    } catch (err) {
      setError(err.message);
    } finally {
      setTriagingAll(false);
    }
  }

  if (!project) {
    return <p style={{ color: "var(--text-muted)" }}>{error || "Loading…"}</p>;
  }

  const inScopeCount = scope.filter((s) => s.in_scope).length;

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 20, fontWeight: 600, margin: "0 0 4px" }}>{project.name}</h1>
        <p style={{ color: "var(--text-muted)", fontSize: 13, margin: 0 }}>
          {project.platform === "bugcrowd" ? "Bugcrowd" : "HackerOne"} · {inScopeCount} in-scope target
          {inScopeCount === 1 ? "" : "s"}
        </p>
      </div>

      <Section title="Pipeline">
        <PipelineTracker phaseRuns={phaseRuns} />
        <div style={{ marginTop: 20 }}>
          <button onClick={handleStartScan} disabled={scanStarting || inScopeCount === 0} style={primaryButtonStyle}>
            {scanStarting ? "Starting…" : "Start scan"}
          </button>
          {inScopeCount === 0 && (
            <span style={{ marginLeft: 12, fontSize: 13, color: "var(--text-muted)" }}>
              Add an in-scope target before scanning.
            </span>
          )}
        </div>
      </Section>

      <Section title="Scope">
        <div style={{ border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", overflow: "hidden" }}>
          {scope.length === 0 ? (
            <div style={{ padding: 16, color: "var(--text-muted)", fontSize: 13 }}>No targets added yet.</div>
          ) : (
            scope.map((s, i) => (
              <div
                key={s.id}
                style={{
                  display: "flex",
                  gap: 12,
                  alignItems: "center",
                  padding: "10px 14px",
                  borderBottom: i < scope.length - 1 ? "1px solid var(--border)" : "none",
                  opacity: s.in_scope ? 1 : 0.5,
                }}
              >
                <span className="mono" style={{ flex: 1, fontSize: 13 }}>
                  {s.target}
                </span>
                <span style={{ fontSize: 12, color: "var(--text-muted)" }}>{s.target_type}</span>
                <span style={{ fontSize: 12, color: s.in_scope ? "var(--status-success)" : "var(--text-muted)" }}>
                  {s.in_scope ? "In scope" : "Out of scope"}
                </span>
              </div>
            ))
          )}
        </div>
      </Section>

      <Section title="Findings">
        {findings.length > 0 && (
          <div style={{ marginBottom: 12 }}>
            <button onClick={handleTriageAll} disabled={triagingAll} style={secondaryButtonStyle}>
              {triagingAll ? "Triaging…" : "Triage all untriaged findings"}
            </button>
          </div>
        )}
        <FindingsList findings={findings} onTriaged={loadAll} />
      </Section>

      {error && <p style={{ color: "var(--status-fail)", fontSize: 13 }}>{error}</p>}
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div style={{ marginBottom: 32 }}>
      <h2 style={{ fontSize: 14, fontWeight: 600, color: "var(--text-secondary)", margin: "0 0 12px", textTransform: "uppercase", letterSpacing: "0.04em" }}>
        {title}
      </h2>
      {children}
    </div>
  );
}

const primaryButtonStyle = {
  background: "var(--accent)",
  color: "var(--on-accent)",
  border: "none",
  borderRadius: "var(--radius)",
  padding: "8px 16px",
  fontSize: 14,
  fontWeight: 500,
  cursor: "pointer",
};

const secondaryButtonStyle = {
  background: "transparent",
  color: "var(--text-secondary)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
  padding: "8px 16px",
  fontSize: 14,
  cursor: "pointer",
};
