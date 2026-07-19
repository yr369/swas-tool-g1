import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api } from "../api/client";
import { PipelineTracker } from "../components/PipelineTracker";
import { FindingsList } from "../components/FindingsList";
import { ScanNotesPanel } from "../components/ScanNotesPanel";
import { DiffPanel } from "../components/DiffPanel";
import { ScopeManager } from "../components/ScopeManager";

// Fallback polling interval, used ONLY when the WebSocket isn't
// connected (never established, or dropped). While the socket is live,
// updates arrive instantly and this interval doesn't fire at all.
const POLL_INTERVAL_MS = 5000;

export function ProjectDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [project, setProject] = useState(null);
  const [scope, setScope] = useState([]);
  const [phaseRuns, setPhaseRuns] = useState([]);
  const [findings, setFindings] = useState([]);
  const [scanNotes, setScanNotes] = useState([]);
  const [scanStarting, setScanStarting] = useState(false);
  const [triagingAll, setTriagingAll] = useState(false);
  const [schedulingBusy, setSchedulingBusy] = useState(false);
  const [runAtValue, setRunAtValue] = useState("");
  const [archiving, setArchiving] = useState(false);
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);
  const [deleteTypedName, setDeleteTypedName] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState(null);
  const [liveConnected, setLiveConnected] = useState(false);
  const pollRef = useRef(null);
  const wsRef = useRef(null);

  const loadAll = useCallback(async () => {
    try {
      const [proj, scopeList, runs, findingsList, notesList] = await Promise.all([
        api.getProject(id),
        api.listScope(id),
        api.listPhaseRuns(id),
        api.listFindings(id),
        api.listScanNotes(id),
      ]);
      setProject(proj);
      setScope(scopeList);
      setPhaseRuns(runs);
      setFindings(findingsList);
      setScanNotes(notesList);
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

  async function handleScheduleChange(intervalHours) {
    setSchedulingBusy(true);
    setError(null);
    try {
      await api.setSchedule(id, intervalHours);
      await loadAll();
    } catch (err) {
      setError(err.message);
    } finally {
      setSchedulingBusy(false);
    }
  }

  async function handleScheduleOnce() {
    if (!runAtValue) return;
    setSchedulingBusy(true);
    setError(null);
    try {
      // datetime-local gives a value with no timezone - the browser
      // interprets it as local time when building a Date, and toISOString()
      // converts that to UTC for the backend, which is what run_at expects.
      const isoRunAt = new Date(runAtValue).toISOString();
      await api.setSchedule(id, project.scan_interval_hours ?? null, isoRunAt);
      setRunAtValue("");
      await loadAll();
    } catch (err) {
      setError(err.message);
    } finally {
      setSchedulingBusy(false);
    }
  }

  async function handleArchive() {
    setArchiving(true);
    setError(null);
    try {
      await api.bulkProjectAction([Number(id)], "archive");
      await loadAll();
    } catch (err) {
      setError(err.message);
    } finally {
      setArchiving(false);
    }
  }

  async function handleConfirmDelete() {
    setDeleting(true);
    setError(null);
    try {
      await api.deleteProject(id, deleteTypedName);
      navigate("/projects");
    } catch (err) {
      setError(err.message);
      setDeleting(false);
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
        <div style={{ marginTop: 20, display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
          <button onClick={handleStartScan} disabled={scanStarting || inScopeCount === 0} style={primaryButtonStyle}>
            {scanStarting ? "Starting…" : "Start scan"}
          </button>
          {inScopeCount === 0 && (
            <span style={{ fontSize: 13, color: "var(--text-muted)" }}>
              Add an in-scope target before scanning.
            </span>
          )}

          <span style={{ display: "flex", alignItems: "center", gap: 8, marginLeft: "auto" }}>
            <label style={{ fontSize: 12, color: "var(--text-muted)" }}>Recurring:</label>
            <select
              value={project.scan_interval_hours ?? ""}
              onChange={(e) => handleScheduleChange(e.target.value ? Number(e.target.value) : null)}
              disabled={schedulingBusy}
              style={scheduleSelectStyle}
            >
              <option value="">Off</option>
              <option value="6">Every 6 hours</option>
              <option value="24">Daily</option>
              <option value="168">Weekly</option>
            </select>
            {project.next_scheduled_scan_at && (
              <span className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>
                next {formatDate(project.next_scheduled_scan_at)}
              </span>
            )}
            <label style={{ fontSize: 12, color: "var(--text-muted)", marginLeft: 8 }}>Run once at:</label>
            <input
              type="datetime-local"
              value={runAtValue}
              onChange={(e) => setRunAtValue(e.target.value)}
              onClick={(e) => {
                // Clicking anywhere in the field opens the native
                // calendar/time picker instead of requiring a precise
                // click on the small calendar icon - without this,
                // clicking the text portion just drops you into manual
                // digit-by-digit typing, which is what felt broken.
                // showPicker() is Chrome/Edge/Firefox 2023+; falls back
                // to default browser behavior everywhere else.
                e.currentTarget.showPicker?.();
              }}
              disabled={schedulingBusy}
              style={scheduleSelectStyle}
            />
            <button
              onClick={handleScheduleOnce}
              disabled={schedulingBusy || !runAtValue}
              style={secondaryButtonStyle}
            >
              Schedule
            </button>
          </span>
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
            <span style={{ display: "flex", gap: 12 }}>
              <a href={api.reportUrl(id)} style={{ fontSize: 12, color: "var(--accent)" }}>
                Download report (.md)
              </a>
              <a href={api.exportFindingsUrl(id)} style={{ fontSize: 12, color: "var(--accent)" }}>
                Export CSV
              </a>
            </span>
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

      <Section title="Notes for manual review">
        <ScanNotesPanel projectId={id} notes={scanNotes} onDismissed={loadAll} />
      </Section>

      <Section title="Danger zone">
        <div style={{ display: "flex", gap: 12 }}>
          <button onClick={handleArchive} disabled={archiving || project.status === "archived"} style={secondaryButtonStyle}>
            {project.status === "archived" ? "Archived" : archiving ? "Archiving…" : "Archive project"}
          </button>
          <button
            onClick={() => { setDeleteTypedName(""); setDeleteModalOpen(true); }}
            style={{ ...secondaryButtonStyle, color: "var(--status-fail)", borderColor: "var(--status-fail)" }}
          >
            Delete project…
          </button>
        </div>
        <p style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 8 }}>
          Archiving is reversible - it just takes the project off the active
          list. Deleting is permanent and removes all findings, scope, and
          scan history for this project.
        </p>
      </Section>

      {deleteModalOpen && (
        <div
          style={{
            position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)",
            display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100,
          }}
          onClick={() => !deleting && setDeleteModalOpen(false)}
        >
          <div
            style={{
              background: "var(--bg-surface-raised)", border: "1px solid var(--border)",
              borderRadius: "var(--radius)", padding: 24, width: 420, maxWidth: "90vw",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <h3 style={{ margin: "0 0 8px", fontSize: 16 }}>Delete “{project.name}”?</h3>
            <p style={{ fontSize: 13, color: "var(--text-muted)", margin: "0 0 16px" }}>
              This permanently deletes this project and every finding, scope
              target, and scan run attached to it. This cannot be undone. Type
              the project name exactly to confirm.
            </p>
            <input
              type="text"
              value={deleteTypedName}
              onChange={(e) => setDeleteTypedName(e.target.value)}
              placeholder={project.name}
              autoFocus
              style={{ ...scheduleSelectStyle, width: "100%", boxSizing: "border-box", padding: "8px 10px", fontSize: 13, marginBottom: 16 }}
            />
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
              <button onClick={() => setDeleteModalOpen(false)} disabled={deleting} style={secondaryButtonStyle}>
                Cancel
              </button>
              <button
                onClick={handleConfirmDelete}
                disabled={deleting || deleteTypedName !== project.name}
                style={{
                  ...primaryButtonStyle,
                  background: "var(--status-fail)",
                  opacity: deleteTypedName !== project.name ? 0.5 : 1,
                }}
              >
                {deleting ? "Deleting…" : "Delete permanently"}
              </button>
            </div>
          </div>
        </div>
      )}

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

const scheduleSelectStyle = {
  background: "var(--bg-surface-raised)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
  color: "var(--text-primary)",
  padding: "5px 8px",
  fontSize: 12,
  fontFamily: "var(--font-ui)",
};

function formatDate(isoString) {
  const date = new Date(isoString);
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }) +
    " · " + date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}
