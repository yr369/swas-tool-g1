import { useEffect, useState } from "react";
import { api } from "../api/client";

function formatDuration(seconds) {
  if (!seconds) return null;
  const mins = Math.round(seconds / 60);
  if (mins < 1) return "<1m";
  if (mins < 60) return `~${mins}m`;
  return `~${(mins / 60).toFixed(1)}h`;
}

// Screenshot capture is opt-in server-side (see screenshots.py) - most
// installs won't have it enabled, so a 404 here just means "not
// available", not an error worth showing. Renders nothing on failure.
function ScreenshotThumb({ targetId }) {
  const [failed, setFailed] = useState(false);
  if (failed) return null;
  return (
    <img
      src={api.screenshotUrl(targetId)}
      alt=""
      onError={() => setFailed(true)}
      style={{ width: 48, height: 32, objectFit: "cover", borderRadius: 3, border: "1px solid var(--border)" }}
    />
  );
}

export function ScopeInsights({ projectId }) {
  const [overlaps, setOverlaps] = useState(null);
  const [estimates, setEstimates] = useState(null);

  useEffect(() => {
    api.listScopeOverlaps(projectId).then(setOverlaps).catch(() => setOverlaps([]));
    api.listDurationEstimates(projectId).then(setEstimates).catch(() => setEstimates([]));
  }, [projectId]);

  const hasOverlaps = overlaps && overlaps.length > 0;
  const hasEstimates = estimates && estimates.some((e) => e.estimated_seconds);

  if (!hasOverlaps && !hasEstimates) return null;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 16 }}>
      {hasOverlaps && (
        <div className="ops-panel" data-label="OVERLAP" style={{ padding: "10px 14px" }}>
          <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 6 }}>
            Already covered by an existing wildcard - advisory only, nothing was blocked:
          </div>
          {overlaps.map((o) => (
            <div key={o.target_id} className="mono" style={{ fontSize: 12, color: "var(--text-muted)" }}>
              {o.target} <span style={{ color: "var(--text-secondary)" }}>→ covered by {o.covered_by}</span>
            </div>
          ))}
        </div>
      )}
      {estimates && estimates.length > 0 && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
          {estimates.map((e) => {
            const dur = formatDuration(e.estimated_seconds);
            return (
              <div
                key={e.target_id}
                className="chip"
                style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11 }}
                title={e.target}
              >
                <ScreenshotThumb targetId={e.target_id} />
                <span className="mono">{e.target}</span>
                {dur && <span style={{ color: "var(--text-muted)" }}>{dur} est.</span>}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
