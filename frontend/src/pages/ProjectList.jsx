import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";

export function ProjectList() {
  const [projects, setProjects] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api
      .listProjects()
      .then(setProjects)
      .catch((err) => setError(err.message));
  }, []);

  if (error) {
    return <p style={{ color: "var(--status-fail)" }}>Couldn't load projects: {error}</p>;
  }

  if (projects === null) {
    return <p style={{ color: "var(--text-muted)" }}>Loading…</p>;
  }

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
        <h1 style={{ fontSize: 20, fontWeight: 600, margin: 0 }}>Projects</h1>
        <Link to="/new" style={newButtonStyle}>
          + New project
        </Link>
      </div>

      {projects.length === 0 ? (
        <div style={{ padding: "48px 16px", textAlign: "center", color: "var(--text-muted)" }}>
          No projects yet. Start by adding a program's scope.
        </div>
      ) : (
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
                <div style={{ fontWeight: 500 }}>{p.name}</div>
                <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>
                  {p.platform === "bugcrowd" ? "Bugcrowd" : "HackerOne"}
                </div>
              </div>
              <StatusPill status={p.status} />
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

function StatusPill({ status }) {
  const label = { created: "Created", scanning: "Scanning", completed: "Completed", archived: "Archived" }[status] || status;
  return (
    <span style={{ fontSize: 12, color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>{label}</span>
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
