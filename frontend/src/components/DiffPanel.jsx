/**
 * DiffPanel.jsx - shows what changed between this project's two most
 * recent scans. Needs at least 2 scans to say anything, so the empty/
 * not-enough-data state is expected and common, not an error.
 */

import { useEffect, useState } from "react";
import { api } from "../api/client";
import { SeverityBadge } from "./FindingsList";

export function DiffPanel({ projectId }) {
  const [diff, setDiff] = useState(null);
  const [status, setStatus] = useState("loading"); // loading | ready | insufficient | error
  const [errorMessage, setErrorMessage] = useState(null);

  useEffect(() => {
    let cancelled = false;
    setStatus("loading");
    api
      .getDiff(projectId)
      .then((result) => {
        if (cancelled) return;
        setDiff(result);
        setStatus("ready");
      })
      .catch((err) => {
        if (cancelled) return;
        // The backend returns 400 specifically for "not enough scans yet" -
        // that's an expected state here, not a real error, so it gets its
        // own quiet message rather than the red error banner.
        if (err.message.toLowerCase().includes("need at least 2 scans")) {
          setStatus("insufficient");
        } else {
          setErrorMessage(err.message);
          setStatus("error");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [projectId]);

  if (status === "loading") {
    return <p style={{ color: "var(--text-muted)", fontSize: 13 }}>Loading…</p>;
  }

  if (status === "insufficient") {
    return (
      <p style={{ color: "var(--text-muted)", fontSize: 13 }}>
        Run a second scan on this project to see what's new or resolved since the last one.
      </p>
    );
  }

  if (status === "error") {
    return <p style={{ color: "var(--status-fail)", fontSize: 13 }}>Couldn't load diff: {errorMessage}</p>;
  }

  const { new_findings, resolved_findings, unchanged_count, baseline_run, latest_run } = diff;

  if (new_findings.length === 0 && resolved_findings.length === 0) {
    return (
      <p style={{ color: "var(--text-muted)", fontSize: 13 }}>
        No change since {formatShort(baseline_run.started_at)} - {unchanged_count} finding
        {unchanged_count === 1 ? "" : "s"} unchanged.
      </p>
    );
  }

  return (
    <div>
      <p style={{ color: "var(--text-muted)", fontSize: 12, marginBottom: 12 }}>
        Comparing scan from {formatShort(baseline_run.started_at)} to {formatShort(latest_run.started_at)} ·{" "}
        {unchanged_count} unchanged
      </p>

      {new_findings.length > 0 && (
        <DiffGroup label={`New (${new_findings.length})`} color="var(--sev-high)" findings={new_findings} />
      )}
      {resolved_findings.length > 0 && (
        <DiffGroup label={`Resolved (${resolved_findings.length})`} color="var(--status-success)" findings={resolved_findings} muted />
      )}
    </div>
  );
}

function DiffGroup({ label, color, findings, muted }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div className="mono" style={{ fontSize: 11, color, textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 6 }}>
        {label}
      </div>
      <div style={{ border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", overflow: "hidden" }}>
        {findings.map((f, i) => (
          <div
            key={f.id}
            style={{
              display: "flex",
              gap: 12,
              alignItems: "center",
              padding: "8px 14px",
              borderBottom: i < findings.length - 1 ? "1px solid var(--border)" : "none",
              opacity: muted ? 0.6 : 1,
            }}
          >
            <SeverityBadge severity={f.severity} />
            <span className="mono" style={{ fontSize: 12, color: "var(--text-secondary)" }}>
              {f.tool_name}
            </span>
            <span
              className="mono"
              style={{
                flex: 1,
                minWidth: 0,
                fontSize: 12,
                color: "var(--text-muted)",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                textDecoration: muted ? "line-through" : "none",
              }}
            >
              {f.evidence}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function formatShort(isoString) {
  const date = new Date(isoString);
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric" }) +
    " " + date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}
