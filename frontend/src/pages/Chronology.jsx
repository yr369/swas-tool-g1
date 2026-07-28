import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { platformLabel } from "../constants";

const STATUS_LABEL = { created: "Created", scanning: "Scanning", completed: "Completed", archived: "Archived" };

const ACTIVITY_LABEL = {
  created: "Project created",
  target_added: "Target added",
  scanned: "Scanned",
  target_rescanned: "Target rescanned",
};

const ACTIVITY_ICON = { created: "+", target_added: "▸", scanned: "◉", target_rescanned: "↻" };

function timeAgo(isoString) {
  const diffMs = Date.now() - new Date(isoString).getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(isoString).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

export function Chronology() {
  const [items, setItems] = useState(null);
  const [error, setError] = useState(null);

  function load() {
    return api
      .listChronology()
      .then(setItems)
      .catch((err) => setError(err.message));
  }

  useEffect(() => {
    load();
    // Chronology is meant to reflect "what's happening right now" - a
    // scan finishing on another target shouldn't require a manual
    // refresh to see the card jump to the top.
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, []);

  if (error) {
    return <p style={{ color: "var(--status-fail)" }}>Couldn't load chronology: {error}</p>;
  }
  if (items === null) {
    return <p style={{ color: "var(--text-muted)" }}>Loading…</p>;
  }

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <div className="eyebrow" style={{ marginBottom: 4 }}>Operator console</div>
        <h1 style={{ fontSize: 24, fontWeight: 500, margin: 0 }}>Chronology</h1>
        <p style={{ fontSize: 13, color: "var(--text-muted)", marginTop: 6 }}>
          Every project, most recent activity first - created, targets added, scanned, or rescanned.
        </p>
      </div>

      {items.length === 0 ? (
        <div style={{ padding: "48px 16px", textAlign: "center", color: "var(--text-muted)" }}>
          No projects yet.
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {items.map((it) => (
            <ChronologyCard key={it.id} it={it} />
          ))}
        </div>
      )}
    </div>
  );
}

function ChronologyCard({ it }) {
  return (
    <Link
      to={`/projects/${it.id}`}
      className="ops-panel"
      data-label={it.status.toUpperCase()}
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 16,
        padding: "14px 18px",
        textDecoration: "none",
        color: "var(--text-primary)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 14, minWidth: 0 }}>
        <span
          aria-hidden="true"
          className="mono"
          title={ACTIVITY_LABEL[it.activity_type]}
          style={{
            width: 26, height: 26, flexShrink: 0, borderRadius: "50%",
            display: "flex", alignItems: "center", justifyContent: "center",
            background: "var(--accent-dim)", color: "var(--accent)", fontSize: 13,
          }}
        >
          {ACTIVITY_ICON[it.activity_type] || "•"}
        </span>
        <div style={{ minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontWeight: 500, fontSize: 14, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
              {it.name}
            </span>
            <span className="chip" style={{ fontSize: 10 }}>{platformLabel(it.platform)}</span>
            {it.wildcard_count > 0 && (
              <span className="chip" style={{ fontSize: 10 }} title={`${it.wildcard_count} wildcard target(s)`}>
                *.wildcard
              </span>
            )}
          </div>
          <div style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 2 }}>
            {ACTIVITY_LABEL[it.activity_type]}
            {it.activity_type === "target_added" && it.latest_target_added && `: ${it.latest_target_added}`}
            {it.activity_type === "target_rescanned" && it.latest_scanned_target && `: ${it.latest_scanned_target}`}
            {" · "}
            {it.target_count} target{it.target_count === 1 ? "" : "s"}
            {it.scan_run_count > 0 && ` · ${it.scan_run_count} scan${it.scan_run_count === 1 ? "" : "s"} run`}
          </div>
        </div>
      </div>
      <div style={{ textAlign: "right", flexShrink: 0 }}>
        <div className="mono" style={{ fontSize: 12, color: "var(--text-secondary)" }}>{timeAgo(it.activity_at)}</div>
        <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>{STATUS_LABEL[it.status]}</div>
      </div>
    </Link>
  );
}
