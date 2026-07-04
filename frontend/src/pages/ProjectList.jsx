import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { Donut } from "../components/charts/Donut";

const STATUS_LABEL = { created: "Created", scanning: "Scanning", completed: "Completed", archived: "Archived" };
const STATUS_ORDER = ["scanning", "created", "completed", "archived"];

export function ProjectList() {
  const [projects, setProjects] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api
      .listProjects()
      .then(setProjects)
      .catch((err) => setError(err.message));
  }, []);

  const statusCounts = useMemo(() => {
    if (!projects) return null;
    const c = Object.fromEntries(STATUS_ORDER.map((s) => [s, 0]));
    for (const p of projects) {
      if (p.status in c) c[p.status] += 1;
    }
    return c;
  }, [projects]);

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

          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {projects.map((p) => (
              <Link
                key={p.id}
                to={`/projects/${p.id}`}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  padding: "14px 16px",
                  background: "var(--bg-surface)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-lg)",
                  textDecoration: "none",
                  color: "var(--text-primary)",
                }}
              >
                <div>
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
