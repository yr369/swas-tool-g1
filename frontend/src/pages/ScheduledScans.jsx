import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { platformLabel } from "../constants";

function formatDate(isoString) {
  const date = new Date(isoString);
  return (
    date.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }) +
    " · " +
    date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
  );
}

export function ScheduledScans() {
  const [projects, setProjects] = useState(null);
  const [error, setError] = useState(null);
  const [cancellingId, setCancellingId] = useState(null);

  function load() {
    return api.listProjects().then(setProjects).catch((err) => setError(err.message));
  }

  useEffect(() => {
    load();
  }, []);

  const scheduled = useMemo(() => {
    if (!projects) return [];
    return projects
      .filter((p) => p.next_scheduled_scan_at)
      .sort((a, b) => new Date(a.next_scheduled_scan_at) - new Date(b.next_scheduled_scan_at));
  }, [projects]);

  async function handleCancel(projectId) {
    setCancellingId(projectId);
    try {
      await api.setSchedule(projectId, null, null);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setCancellingId(null);
    }
  }

  if (error) return <p style={{ color: "var(--status-fail)" }}>Couldn't load: {error}</p>;
  if (projects === null) return <p style={{ color: "var(--text-muted)" }}>Loading…</p>;

  return (
    <div>
      <div className="eyebrow" style={{ marginBottom: 4 }}>Upcoming automated runs</div>
      <h1 style={{ fontSize: 24, fontWeight: 500, margin: "0 0 20px" }}>Scheduled scans</h1>

      {scheduled.length === 0 ? (
        <div style={{ padding: "48px 16px", textAlign: "center", color: "var(--text-muted)" }}>
          Nothing scheduled. Set a recurring interval or a one-time run from a project's Pipeline panel.
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {scheduled.map((p) => (
            <div
              key={p.id}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                padding: "14px 16px",
                background: "var(--bg-surface)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-lg)",
              }}
            >
              <Link to={`/projects/${p.id}`} style={{ flex: 1, color: "var(--text-primary)", textDecoration: "none", minWidth: 0 }}>
                <div style={{ fontWeight: 500 }}>{p.name}</div>
                <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>
                  {platformLabel(p.platform)}
                  {p.scan_interval_hours && <> · every {p.scan_interval_hours}h</>}
                </div>
              </Link>
              <span className="mono" style={{ fontSize: 12, color: "var(--signal)" }}>
                next {formatDate(p.next_scheduled_scan_at)}
              </span>
              <button
                className="btn btn-danger"
                onClick={() => handleCancel(p.id)}
                disabled={cancellingId === p.id}
              >
                {cancellingId === p.id ? "…" : "Cancel"}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
