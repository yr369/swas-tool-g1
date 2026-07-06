import { useCallback, useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../api/client";
import { PipelineTracker } from "../components/PipelineTracker";
import { FindingsList } from "../components/FindingsList";
import { DiffPanel } from "../components/DiffPanel";
import { ScopeManager } from "../components/ScopeManager";

// Fallback polling interval, used ONLY when the WebSocket isn't
// connected (never established, or dropped). While the socket is live,
// updates arrive instantly and this interval doesn't fire at all.
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
  const [liveConnected, setLiveConnected] = useState(false);
  const pollRef = useRef(null);
  const wsRef = useRef(null);

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

  // Live updates: open a WebSocket for this project and just re-fetch
  // phase-runs (and findings, since a completed 'scan' phase means new
  // findings likely landed) whenever a phase_update message arrives.
  // We re-fetch rather than trying to patch state from the message
  // itself - simpler, and it's cheap since these are small payloads.
  useEffect(() => {
    let cancelled = false;
    const ws = new WebSocket(api.progressSocketUrl(id));
    wsRef.current = ws;

    ws.onopen = () => {
      if (!cancelled) setLiveConnected(true);
    };
    ws.onmessage = () => {
      if (!cancelled) loadAll();
    };
    ws.onclose = () => {
      if (!cancelled) setLiveConnected(false);
    };
    ws.onerror = () => {
      // onclose fires right after this too - nothing extra to do here,
      // just avoid an unhandled-error console spam on repeated retries.
    };

    return () => {
      cancelled = true;
      ws.close();
    };
  }, [id, loadAll]);

  // Fallback polling: only runs while something looks actively in
  // progress AND the WebSocket isn't currently connected. Once the
  // socket connects, this interval is skipped entirely - the socket is
  // strictly faster and cheaper.
  useEffect(() => {
    const isActive = phaseRuns.some((r) => r.status === "in_progress" || r.status === "pending");
    if (isActive && !liveConnected) {
      pollRef.current = setInterval(loadAll, POLL_INTERVAL_MS);
      return () => clearInterval(pollRef.current);
    }
  }, [phaseRuns, liveConnected, loadAll]);

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
        <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
          <h1 style={{ fontSize: 20, fontWeight: 600, margin: "0 0 4px" }}>{project.name}</h1>
          <span className="mono" style={{ fontSize: 12, color: "var(--text-muted)" }}>#{project.id}</span>
        </div>
        <p style={{ color: "var(--text-muted)", fontSize: 13, margin: 0 }}>
          {project.platform === "bugcrowd" ? "Bugcrowd" : "HackerOne"} · {inScopeCount} in-scope target
          {inScopeCount === 1 ? "" : "s"} · Created {formatDate(project.created_at)}
        </p>
      </div>

      <Section
        title="Pipeline"
        aside={
          <span
            className="mono"
            style={{ fontSize: 11, color: liveConnected ? "var(--signal)" : "var(--text-muted)", display: "flex", alignItems: "center", gap: 6 }}
          >
            <span
              aria-hidden="true"
              style={{
                width: 6,
                height: 6,
                borderRadius: "50%",
                background: liveConnected ? "var(--signal)" : "var(--text-muted)",
                animation: liveConnected ? "signal-pulse 1.8s ease-out infinite" : "none",
              }}
            />
            {liveConnected ? "LIVE" : "POLLING"}
          </span>
        }
      >
        <PipelineTracker phaseRuns={phaseRuns} />
        <div style={{ marginTop: 20, display: "flex", alignItems: "center", gap: 12 }}>
          <button onClick={handleStartScan} disabled={scanStarting || inScopeCount === 0} style={primaryButtonStyle}>
            {scanStarting ? "Starting…" : "Start scan"}
          </button>
          {inScopeCount === 0 && (
            <span style={{ fontSize: 13, color: "var(--text-muted)" }}>
              Add an in-scope target before scanning.
            </span>
          )}
        </div>
      </Section>

      <Section title="Scope">
        <ScopeManager projectId={id} scope={scope} onChange={loadAll} />
      </Section>

      <Section title="Changes since last scan">
        <DiffPanel projectId={id} />
      </Section>

      <Section
        title="Findings"
        aside={
          findings.length > 0 && (
            <a href={api.exportFindingsUrl(id)} style={{ fontSize: 12, color: "var(--accent)" }}>
              Export CSV
            </a>
          )
        }
      >
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

function Section({ title, aside, children }) {
  return (
    <div style={{ marginBottom: 32 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <h2 style={{ fontSize: 14, fontWeight: 600, color: "var(--text-secondary)", margin: 0, textTransform: "uppercase", letterSpacing: "0.04em" }}>
          {title}
        </h2>
        {aside}
      </div>
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

function formatDate(isoString) {
  const date = new Date(isoString);
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }) +
    " · " + date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}
