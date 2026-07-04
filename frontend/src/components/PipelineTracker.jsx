/**
 * PipelineTracker.jsx - the signature visual of the whole app.
 *
 * Shows the 5-phase pipeline (recon -> probe -> fuzz -> scan -> notify)
 * as connected stages. Each stage's color reflects its real status from
 * the backend's phase_runs table - this isn't decorative, it's a direct
 * readout of the checkpoint table we built and tested earlier.
 */

const PHASES = ["recon", "probe", "fuzz", "scan", "notify"];

function statusForPhase(phaseRuns, phaseName) {
  // A phase can have multiple historical runs (e.g. re-scanned later).
  // We want the most recent one for this phase.
  const runs = phaseRuns
    .filter((r) => r.phase_name === phaseName)
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  return runs[0]?.status || "not_started";
}

const STATUS_COLOR = {
  completed: "var(--status-success)",
  in_progress: "var(--signal)",
  failed: "var(--status-fail)",
  needs_attention: "var(--sev-high)",
  pending: "var(--status-pending)",
  not_started: "var(--border-strong)",
};

export function PipelineTracker({ phaseRuns }) {
  return (
    <div style={{ display: "flex", alignItems: "center", width: "100%" }}>
      {PHASES.map((phase, i) => {
        const status = statusForPhase(phaseRuns, phase);
        const color = STATUS_COLOR[status];
        const isLast = i === PHASES.length - 1;
        const isActive = status === "in_progress";

        return (
          <div key={phase} style={{ display: "flex", alignItems: "center", flex: isLast ? "0 0 auto" : 1 }}>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
              <div
                style={{
                  position: "relative",
                  width: 14,
                  height: 14,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                {isActive && (
                  // The one deliberately animated moment in the whole app:
                  // a radar-style sweep on whichever phase is actively
                  // running right now, in the signal accent reserved
                  // exclusively for "this is live". Everything else on
                  // this tracker is a static, disciplined readout.
                  <span
                    aria-hidden="true"
                    style={{
                      position: "absolute",
                      inset: -6,
                      borderRadius: "50%",
                      border: "1px solid var(--signal)",
                      borderTopColor: "transparent",
                      borderRightColor: "transparent",
                      animation: "signal-sweep 1.4s linear infinite",
                    }}
                  />
                )}
                <div
                  style={{
                    width: 14,
                    height: 14,
                    borderRadius: "50%",
                    background: status === "not_started" ? "transparent" : color,
                    border: `2px solid ${color}`,
                    animation: isActive ? "signal-pulse 1.8s ease-out infinite" : "none",
                    transition: "background 0.2s",
                  }}
                  aria-hidden="true"
                />
              </div>
              <span
                className="mono"
                style={{
                  fontSize: 12,
                  color: status === "not_started" ? "var(--text-muted)" : "var(--text-secondary)",
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                }}
              >
                {phase}
              </span>
            </div>
            {!isLast && (
              <div
                style={{
                  flex: 1,
                  height: 2,
                  background: status === "completed" ? "var(--status-success)" : "var(--border)",
                  marginBottom: 22,
                  transition: "background 0.2s",
                }}
                aria-hidden="true"
              />
            )}
          </div>
        );
      })}
    </div>
  );
}
