import { useState } from "react";
import { api } from "../api/client";

// Deliberately a plain bar row, not a full chart lib - this is one
// small number-over-time signal on a page that's already dense; a
// heavyweight chart component here would outweigh the value for
// something you glance at, not analyze.
export function OutcomeTrend({ projectId }) {
  const [expanded, setExpanded] = useState(false);
  const [weeks, setWeeks] = useState(null);
  const [err, setErr] = useState(null);

  async function toggle() {
    const next = !expanded;
    setExpanded(next);
    if (next && weeks === null) {
      try {
        setWeeks(await api.getOutcomeTrend(projectId, 12));
      } catch (e) {
        setErr(e.message);
      }
    }
  }

  const maxTotal = weeks && weeks.length ? Math.max(...weeks.map((w) => w.total), 1) : 1;

  return (
    <div className="ops-panel" data-label="Accept rate" style={{ marginBottom: 16, padding: "14px 18px 12px" }}>
      <button className="btn" onClick={toggle}>
        {expanded ? "Hide" : "Show"} accept rate trend
      </button>
      {expanded && (
        <div style={{ marginTop: 14 }}>
          {err && <p style={{ color: "var(--status-fail)", fontSize: 13 }}>{err}</p>}
          {weeks === null && !err && <p style={{ color: "var(--text-muted)", fontSize: 13 }}>Loading…</p>}
          {weeks !== null && weeks.length === 0 && (
            <p style={{ color: "var(--text-muted)", fontSize: 13 }}>Not enough triaged history yet.</p>
          )}
          {weeks !== null && weeks.length > 0 && (
            <>
              <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 8 }}>
                Weekly accept rate (triaged findings that were actually accepted)
              </div>
              <div style={{ display: "flex", alignItems: "flex-end", gap: 4, height: 48 }}>
                {weeks.map((w) => {
                  const height = Math.max(4, (w.total / maxTotal) * 44);
                  const rate = w.accept_rate;
                  const color = rate == null ? "var(--border)" : rate >= 0.5 ? "var(--accent)" : "var(--status-warn)";
                  return (
                    <div
                      key={w.week}
                      title={`${new Date(w.week).toLocaleDateString()}: ${w.accepted}/${w.total} accepted${
                        rate != null ? ` (${Math.round(rate * 100)}%)` : ""
                      }`}
                      style={{ width: 10, height, background: color, borderRadius: 2 }}
                    />
                  );
                })}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
