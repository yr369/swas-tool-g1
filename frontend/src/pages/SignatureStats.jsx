/**
 * SignatureStats.jsx - "which kinds of findings actually get accepted?"
 *
 * A signature is roughly (tool, vuln_type) - this surfaces the same
 * outcome history that triage.py already looks up before scoring a new
 * finding, so the operator can see the pattern directly instead of only
 * having it baked invisibly into AI reasoning text.
 */

import { useEffect, useState } from "react";
import { api } from "../api/client";

const OUTCOME_COLUMNS = [
  { key: "accepted", label: "Accepted", color: "var(--status-success)" },
  { key: "duplicate", label: "Duplicate", color: "var(--sev-low)" },
  { key: "rejected", label: "Rejected", color: "var(--status-fail)" },
  { key: "informative", label: "Informative", color: "var(--text-muted)" },
  { key: "not_applicable", label: "N/A", color: "var(--text-muted)" },
  { key: "no_response", label: "No response", color: "var(--text-muted)" },
];

export function SignatureStats() {
  const [stats, setStats] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api
      .getSignatureStats()
      .then(setStats)
      .catch((err) => setError(err.message));
  }, []);

  if (error) {
    return <p style={{ color: "var(--status-fail)" }}>Couldn't load signature stats: {error}</p>;
  }

  if (stats === null) {
    return <p style={{ color: "var(--text-muted)" }}>Loading…</p>;
  }

  return (
    <div>
      <h1 style={{ fontSize: 22, fontWeight: 600, margin: "0 0 4px" }}>Signature Stats</h1>
      <p style={{ color: "var(--text-muted)", fontSize: 13, margin: "0 0 24px" }}>
        Real outcomes logged per (tool + vuln type) signature - the same history triage checks before scoring a new finding.
      </p>

      {stats.length === 0 ? (
        <div style={{ padding: "48px 16px", textAlign: "center", color: "var(--text-muted)" }}>
          No outcomes logged yet. Log a real outcome on a finding to start building this history.
        </div>
      ) : (
        <div style={{ border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", overflow: "hidden" }}>
          {stats.map((s, i) => (
            <SignatureRow key={s.signature} stat={s} isLast={i === stats.length - 1} />
          ))}
        </div>
      )}
    </div>
  );
}

function SignatureRow({ stat, isLast }) {
  const acceptanceRate = stat.total > 0 ? Math.round((stat.accepted / stat.total) * 100) : 0;

  return (
    <div style={{ padding: "12px 16px", borderBottom: isLast ? "none" : "1px solid var(--border)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 8 }}>
        <span className="mono" style={{ fontSize: 13, fontWeight: 500 }}>
          {stat.signature}
        </span>
        <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
          {stat.total} logged · <span style={{ color: acceptanceRate >= 50 ? "var(--status-success)" : "var(--text-secondary)" }}>{acceptanceRate}% accepted</span>
        </span>
      </div>

      {/* Proportional stacked bar - same visual language as severity
          donuts elsewhere, just linear since there's a natural order
          (accepted is "good", rejected is "bad") that a ring would lose. */}
      <div style={{ display: "flex", height: 6, borderRadius: 3, overflow: "hidden", background: "var(--bg-surface-raised)", marginBottom: 8 }}>
        {OUTCOME_COLUMNS.map((col) => {
          const value = stat[col.key] || 0;
          if (value === 0 || stat.total === 0) return null;
          return (
            <span
              key={col.key}
              style={{ width: `${(value / stat.total) * 100}%`, background: col.color }}
              title={`${col.label}: ${value}`}
            />
          );
        })}
      </div>

      <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
        {OUTCOME_COLUMNS.map((col) => (
          <span key={col.key} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11, color: "var(--text-muted)" }}>
            <span aria-hidden="true" style={{ width: 7, height: 7, borderRadius: 2, background: col.color }} />
            {col.label} <span className="mono">{stat[col.key] || 0}</span>
          </span>
        ))}
      </div>
    </div>
  );
}
