import { useEffect, useState } from "react";
import { api } from "../api/client";

// Deliberately a plain text/bar row, not a full chart lib - this is one
// small number-over-time signal on a page that's already dense; a
// heavyweight chart component here would outweigh the value for
// something you glance at, not analyze.
export function OutcomeTrend({ projectId }) {
  const [weeks, setWeeks] = useState(null);

  useEffect(() => {
    api.getOutcomeTrend(projectId, 12).then(setWeeks).catch(() => setWeeks([]));
  }, [projectId]);

  if (!weeks || weeks.length === 0) return null;

  const maxTotal = Math.max(...weeks.map((w) => w.total), 1);

  return (
    <div className="ops-panel" data-label="ACCEPT RATE" style={{ padding: "12px 16px" }}>
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
    </div>
  );
}
