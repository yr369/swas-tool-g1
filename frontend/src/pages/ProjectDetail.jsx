import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api } from "../api/client";
import { PipelineTracker } from "../components/PipelineTracker";
import { FindingsList } from "../components/FindingsList";
import { ScanNotesPanel } from "../components/ScanNotesPanel";
import { DiffPanel } from "../components/DiffPanel";
import { ScopeManager } from "../components/ScopeManager";
import { PLATFORM_LABEL, platformLabel } from "../constants";

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
  const [diffHasContent, setDiffHasContent] = useState(false);
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

  async function handleCancelSchedule() {
    setSchedulingBusy(true);
    setError(null);
    try {
      // Clearing both interval and one-off run_at is what actually
      // cancels everything pending - a recurring interval AND a
      // one-time run_at can both be set at once, so cancel needs to
      // wipe both, not just whichever one happens to be displayed.
      await api.setSchedule(id, null, null);
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
      <ProjectHeader project={project} inScopeCount={inScopeCount} onSaved={loadAll} />

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
        <div style={{ marginTop: 14, display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
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
              <>
                <span className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>
                  next {formatDate(project.next_scheduled_scan_at)}
                </span>
                <button
                  onClick={handleCancelSchedule}
                  disabled={schedulingBusy}
                  style={{ ...secondaryButtonStyle, color: "var(--status-fail)" }}
                >
                  Cancel
                </button>
              </>
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

      <ScanHistorySection projectId={id} />

      <Section title="Scope">
        <ScopeManager projectId={id} scope={scope} onChange={loadAll} />
      </Section>

      <div style={{ display: diffHasContent ? "block" : "none" }}>
        <Section title="Changes since last scan">
          <DiffPanel projectId={id} onHasContent={setDiffHasContent} />
        </Section>
      </div>

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

function ProjectHeader({ project, inScopeCount, onSaved }) {
  const [editing, setEditing] = useState(false);
  const [nameValue, setNameValue] = useState(project.name);
  const [platformValue, setPlatformValue] = useState(project.platform);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState(null);

  function startEditing() {
    setNameValue(project.name);
    setPlatformValue(project.platform);
    setErr(null);
    setEditing(true);
  }

  async function save() {
    if (!nameValue.trim()) {
      setErr("Name can't be empty.");
      return;
    }
    setSaving(true);
    setErr(null);
    try {
      const patch = {};
      if (nameValue.trim() !== project.name) patch.name = nameValue.trim();
      if (platformValue !== project.platform) patch.platform = platformValue;
      if (Object.keys(patch).length > 0) {
        await api.updateProject(project.id, patch);
        await onSaved();
      }
      setEditing(false);
    } catch (e) {
      setErr(e.message);
    } finally {
      setSaving(false);
    }
  }

  if (editing) {
    return (
      <div style={{ marginBottom: 20 }}>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <input
            type="text"
            value={nameValue}
            onChange={(e) => setNameValue(e.target.value)}
            className="input"
            style={{ fontSize: 18, fontWeight: 500, maxWidth: 320 }}
            autoFocus
          />
          <select value={platformValue} onChange={(e) => setPlatformValue(e.target.value)} className="input">
            {Object.entries(PLATFORM_LABEL).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
          <button className="btn btn-primary" onClick={save} disabled={saving}>
            {saving ? "Saving…" : "Save"}
          </button>
          <button className="btn" onClick={() => setEditing(false)} disabled={saving}>
            Cancel
          </button>
        </div>
        {err && <p style={{ color: "var(--status-fail)", fontSize: 13, margin: "6px 0 0" }}>{err}</p>}
      </div>
    );
  }

  return (
    <div style={{ marginBottom: 24 }}>
      <div className="eyebrow" style={{ marginBottom: 4 }}>
        {platformLabel(project.platform)} target
      </div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
        <h1 style={{ fontSize: 22, fontWeight: 500, margin: "0 0 4px" }}>{project.name}</h1>
        <span className="mono" style={{ fontSize: 12, color: "var(--text-muted)" }}>#{project.id}</span>
        <button className="btn" onClick={startEditing} style={{ padding: "3px 9px", fontSize: 11 }}>
          Edit
        </button>
      </div>
      <p style={{ color: "var(--text-muted)", fontSize: 13, margin: 0 }}>
        {platformLabel(project.platform)} · {inScopeCount} in-scope target
        {inScopeCount === 1 ? "" : "s"} · Created {formatDate(project.created_at)}
      </p>
    </div>
  );
}

function ScanHistorySection({ projectId }) {
  const [expanded, setExpanded] = useState(false);
  const [runs, setRuns] = useState(null);
  const [err, setErr] = useState(null);

  async function toggle() {
    const next = !expanded;
    setExpanded(next);
    if (next && runs === null) {
      try {
        setRuns(await api.listScanRuns(projectId));
      } catch (e) {
        setErr(e.message);
      }
    }
  }

  return (
    <div className="ops-panel" data-label="Scan history" style={{ marginBottom: 16, padding: "14px 18px 12px" }}>
      <button className="btn" onClick={toggle}>
        {expanded ? "Hide" : "Show"} scan history{runs !== null ? ` (${runs.length})` : ""}
      </button>
      {expanded && (
        <div style={{ marginTop: 14 }}>
          {err && <p style={{ color: "var(--status-fail)", fontSize: 13 }}>{err}</p>}
          {runs === null && !err && <p style={{ color: "var(--text-muted)", fontSize: 13 }}>Loading…</p>}
          {runs !== null && runs.length === 0 && (
            <p style={{ color: "var(--text-muted)", fontSize: 13 }}>No scans run yet.</p>
          )}
          {runs !== null && runs.length > 0 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {runs.map((r) => (
                <div key={r.id} className="mono" style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                  {formatDate(r.started_at)}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Section({ title, aside, children }) {
  return (
    <div className="ops-panel" data-label={title} style={{ marginBottom: 16, padding: "14px 18px 12px" }}>
      {aside && (
        <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 10 }}>
          {aside}
        </div>
      )}
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
