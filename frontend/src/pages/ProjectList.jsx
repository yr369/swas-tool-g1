import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { Donut } from "../components/charts/Donut";

const STATUS_LABEL = { created: "Created", scanning: "Scanning", completed: "Completed", archived: "Archived" };
const STATUS_ORDER = ["scanning", "created", "completed", "archived"];

export function ProjectList() {
  const [projects, setProjects] = useState(null);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(() => new Set());
  const [bulkRunning, setBulkRunning] = useState(false);
  const [bulkResult, setBulkResult] = useState(null);

  function load() {
    return api
      .listProjects()
      .then((data) => {
        setProjects(data);
        // Drop selections for projects that no longer exist (e.g. after
        // a bulk delete) rather than leaving stale ids checked.
        setSelected((prev) => new Set([...prev].filter((id) => data.some((p) => p.id === id))));
      })
      .catch((err) => setError(err.message));
  }

  useEffect(() => {
    load();
  }, []);

  const statusCounts = useMemo(() => {
    if (!projects) return null;
    const c = Object.fromEntries(STATUS_ORDER.map((s) => [s, 0]));
    for (const p of projects) {
      if (p.status in c) c[p.status] += 1;
    }
    return c;
  }, [projects]);

  function toggleOne(id) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAll() {
    setSelected((prev) => (prev.size === projects.length ? new Set() : new Set(projects.map((p) => p.id))));
  }

  async function handleBulkAction(action) {
    if (action === "delete") {
      const confirmed = window.confirm( // eslint-disable-line no-alert -- plain confirm is fine for a solo-operator internal tool
        `Delete ${selected.size} project${selected.size === 1 ? "" : "s"}? Projects with findings attached will be skipped, not deleted.`
      );
      if (!confirmed) return;
    }
    setBulkRunning(true);
    setBulkResult(null);
    try {
      const result = await api.bulkProjectAction([...selected], action);
      setBulkResult(result);
      setSelected(new Set());
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBulkRunning(false);
    }
  }

  if (error) {
    return <p style={{ color: "var(--status-fail)" }}>Couldn't load projects: {error}</p>;
  }

  if (projects === null) {
    return <p style={{ color: "var(--text-muted)" }}>Loading…</p>;
  }

  const donutSegments = STATUS_ORDER.map((s) => ({
    key: s,
    label: STATUS_LABEL[s],
    value: statusCounts[s],
    color: `var(--proj-${s})`,
  }));

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 600, margin: 0 }}>Projects</h1>
        <Link to="/new" style={newButtonStyle}>
          + New project
        </Link>
      </div>

      {projects.length === 0 ? (
        <div style={{ padding: "48px 16px", textAlign: "center", color: "var(--text-muted)" }}>
          No projects yet. Start by adding a program's scope.
        </div>
      ) : (
        <>
          <div
            style={{
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-lg)",
              background: "var(--bg-surface)",
              padding: "18px 20px",
              marginBottom: 20,
            }}
          >
            <Donut segments={donutSegments} centerLabel="projects by status" />
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
            <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--text-secondary)" }}>
              <input
                type="checkbox"
                checked={selected.size === projects.length}
                onChange={toggleAll}
                ref={(el) => {
                  if (el) el.indeterminate = selected.size > 0 && selected.size < projects.length;
                }}
              />
              Select all
            </label>

            {selected.size > 0 && (
              <>
                <span style={{ fontSize: 12, color: "var(--text-muted)" }}>{selected.size} selected</span>
                <button onClick={() => handleBulkAction("archive")} disabled={bulkRunning} style={secondaryButtonStyle}>
                  {bulkRunning ? "…" : "Archive selected"}
                </button>
                <button
                  onClick={() => handleBulkAction("delete")}
                  disabled={bulkRunning}
                  style={{ ...secondaryButtonStyle, color: "var(--status-fail)" }}
                >
                  {bulkRunning ? "…" : "Delete selected"}
                </button>
              </>
            )}
          </div>

          {bulkResult && (
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 12 }}>
              {bulkResult.action === "archive" ? (
                <span style={{ color: "var(--status-success)" }}>Archived {bulkResult.succeeded.length}.</span>
              ) : (
                <span style={{ color: "var(--status-success)" }}>Deleted {bulkResult.succeeded.length}.</span>
              )}
              {bulkResult.blocked.length > 0 && (
                <div style={{ color: "var(--sev-medium)", marginTop: 4 }}>
                  Skipped {bulkResult.blocked.length} (has findings - set to archived instead if you want it out of the active list):{" "}
                  {bulkResult.blocked.map((b) => `${b.name} (${b.reason})`).join(", ")}
                </div>
              )}
            </div>
          )}

          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {projects.map((p) => (
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
                <input
                  type="checkbox"
                  checked={selected.has(p.id)}
                  onChange={() => toggleOne(p.id)}
                  onClick={(e) => e.stopPropagation()}
                />
                <Link
                  to={`/projects/${p.id}`}
                  style={{
                    flex: 1,
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    textDecoration: "none",
                    color: "var(--text-primary)",
                    minWidth: 0,
                  }}
                >
                  <div style={{ minWidth: 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span style={{ fontWeight: 500 }}>{p.name}</span>
                      <span className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>
                        #{p.id}
                      </span>
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>
                      {p.platform === "bugcrowd" ? "Bugcrowd" : "HackerOne"} · {formatDate(p.created_at)}
                    </div>
                  </div>
                  <StatusPill status={p.status} />
                </Link>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function formatDate(isoString) {
  const date = new Date(isoString);
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }) +
    " · " + date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

function StatusPill({ status }) {
  const label = STATUS_LABEL[status] || status;
  const color = status in STATUS_LABEL ? `var(--proj-${status})` : "var(--text-muted)";
  const isLive = status === "scanning";
  return (
    <span
      className="mono"
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        fontSize: 12,
        color,
        border: `1px solid ${color}`,
        borderRadius: 999,
        padding: "3px 10px",
      }}
    >
      {isLive && (
        <span
          aria-hidden="true"
          style={{ width: 6, height: 6, borderRadius: "50%", background: color, animation: "signal-pulse 1.6s ease-out infinite" }}
        />
      )}
      {label}
    </span>
  );
}

const newButtonStyle = {
  background: "var(--accent)",
  color: "var(--on-accent)",
  border: "none",
  borderRadius: "var(--radius)",
  padding: "8px 16px",
  fontSize: 14,
  fontWeight: 500,
  textDecoration: "none",
};

const secondaryButtonStyle = {
  background: "transparent",
  color: "var(--text-secondary)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
  padding: "5px 12px",
  fontSize: 12,
  cursor: "pointer",
};
