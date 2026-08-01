/**
 * Observability.jsx - the operational twin of Dashboard.jsx.
 *
 * Dashboard.jsx answers "what's the worst finding across everything I'm
 * running right now". This answers "is the pipeline itself healthy" -
 * AI rotation, tool binaries, retry queue backlog, evidence going stale,
 * targets that quietly died. All of that already existed as backend
 * state (/api/health/dashboard, batches 25-27) with nothing rendering
 * it - this page is the first frontend consumer of that endpoint.
 *
 * Polls on a timer since this is a "leave it open on a second monitor"
 * page, not a one-shot load.
 */

import { useEffect, useState } from "react";
import { api } from "../api/client";

const POLL_MS = 30_000;

export function Observability() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [lastFetched, setLastFetched] = useState(null);

  useEffect(() => {
    let cancelled = false;

    function load() {
      api
        .healthDashboard()
        .then((d) => {
          if (cancelled) return;
          setData(d);
          setError(null);
          setLastFetched(new Date());
        })
        .catch((err) => {
          if (!cancelled) setError(err.message);
        });
    }

    load();
    const handle = setInterval(load, POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(handle);
    };
  }, []);

  if (error && !data) {
    return <p style={{ color: "var(--status-fail)" }}>Couldn't load system status: {error}</p>;
  }

  if (!data) {
    return <p style={{ color: "var(--text-muted)" }}>Loading…</p>;
  }

  const totalFailures24h = data.recent_phase_failures_24h.reduce((sum, r) => sum + r.count, 0);
  const totalRetryPending = data.retry_queue.reduce((sum, r) => sum + r.pending, 0);
  const missingBinaries = Object.entries(data.tools.binaries_present).filter(([, present]) => !present);
  const driftedCanaries = data.canary_targets.filter((c) => c.drifted);

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: 24 }}>
        <div>
          <div className="eyebrow" style={{ marginBottom: 4 }}>Pipeline health, not finding severity</div>
          <h1 style={{ fontSize: 24, fontWeight: 500, margin: 0 }}>System</h1>
        </div>
        {lastFetched && (
          <span style={{ fontSize: 11, color: "var(--text-muted)" }} className="mono">
            updated {lastFetched.toLocaleTimeString()}
          </span>
        )}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 16 }}>
        <Panel label="DATABASE">
          <StatusLine ok={data.database_ok} okText="Connected" badText="Unreachable" />
        </Panel>

        <Panel label="AI ROTATION">
          <CircuitBreaker status={data.ai.circuit_breaker} />
          {data.ai.usage_today && typeof data.ai.usage_today === "object" && !data.ai.usage_today.error && (
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 6 }} className="mono">
              {Object.entries(data.ai.usage_today)
                .map(([model, n]) => `${model}: ${n}`)
                .join("  ·  ")}
            </div>
          )}
        </Panel>

        <Panel label="TOOL BINARIES">
          {missingBinaries.length === 0 ? (
            <StatusLine ok okText="All present" />
          ) : (
            <div>
              <StatusLine ok={false} badText={`${missingBinaries.length} missing`} />
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }} className="mono">
                {missingBinaries.map(([name]) => name).join(", ")}
              </div>
            </div>
          )}
          {data.tools.version_drift && !data.tools.version_drift.error && Array.isArray(data.tools.version_drift) && data.tools.version_drift.length > 0 && (
            <div style={{ fontSize: 11, color: "var(--sev-medium)", marginTop: 6 }}>
              {data.tools.version_drift.length} version{data.tools.version_drift.length === 1 ? "" : "s"} drifted from pinned
            </div>
          )}
        </Panel>

        <Panel label="OOB / INTERACTSH">
          <StatusLine ok={data.oob_available} okText="Available" badText="Unavailable" />
        </Panel>

        <Panel label="RETRY QUEUE" accent={totalRetryPending > 0 ? "var(--sev-medium)" : undefined}>
          {data.retry_queue.length === 0 ? (
            <StatusLine ok okText="Empty" />
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {data.retry_queue.map((r) => (
                <div key={r.kind} style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
                  <span className="mono">{r.kind}</span>
                  <span style={{ color: r.pending > 0 ? "var(--sev-medium)" : "var(--text-muted)" }}>
                    {r.pending} pending{r.failed_24h > 0 ? `, ${r.failed_24h} failed/24h` : ""}
                  </span>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel label="EVIDENCE INTEGRITY (7d)" accent={data.evidence.rotted_7d > 0 ? "var(--sev-medium)" : undefined}>
          <div style={{ display: "flex", gap: 16, fontSize: 12 }}>
            <span>
              <span style={{ color: "var(--status-success)" }}>{data.evidence.reproducible_7d}</span> reproducible
            </span>
            <span>
              <span style={{ color: data.evidence.rotted_7d > 0 ? "var(--sev-medium)" : "var(--text-muted)" }}>
                {data.evidence.rotted_7d}
              </span>{" "}
              rotted
            </span>
          </div>
        </Panel>

        <Panel label="PHASE FAILURES (24h)" accent={totalFailures24h > 0 ? "var(--status-fail)" : undefined}>
          {data.recent_phase_failures_24h.length === 0 ? (
            <StatusLine ok okText="None" />
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {data.recent_phase_failures_24h.map((r, i) => (
                <div key={i} style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
                  <span className="mono">{r.phase} · {r.status}</span>
                  <span style={{ color: "var(--status-fail)" }}>{r.count}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel label="CANARY DRIFT" accent={driftedCanaries.length > 0 ? "var(--status-fail)" : undefined}>
          {data.canary_targets.length === 0 ? (
            <span style={{ fontSize: 12, color: "var(--text-muted)" }}>No canary projects configured</span>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {data.canary_targets.map((c) => (
                <div key={c.project_id} style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
                  <span>{c.project_name}</span>
                  <span style={{ color: c.drifted ? "var(--status-fail)" : "var(--status-success)" }}>
                    {c.current_finding_count} / baseline {c.baseline_finding_count ?? "—"}
                  </span>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      {data.evidence.dead_targets.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <div className="ops-panel" data-label={`DEAD TARGETS · ${data.evidence.dead_targets.length}`} style={{ overflow: "hidden" }}>
            {data.evidence.dead_targets.map((t, i) => (
              <div
                key={t.target_id}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  padding: "10px 16px",
                  borderBottom: i < data.evidence.dead_targets.length - 1 ? "1px solid var(--border)" : "none",
                  fontSize: 12,
                }}
              >
                <div>
                  <span className="mono">{t.target}</span>
                  <span style={{ color: "var(--text-muted)", marginLeft: 8 }}>({t.project_name})</span>
                </div>
                <span style={{ color: "var(--text-muted)" }}>
                  {t.dead_since ? `dark since ${new Date(t.dead_since).toLocaleDateString()}` : ""}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function Panel({ label, accent, children }) {
  return (
    <div
      className="ops-panel"
      data-label={label}
      style={{ padding: 16, borderColor: accent || undefined }}
    >
      {children}
    </div>
  );
}

function StatusLine({ ok, okText = "OK", badText = "Down" }) {
  return (
    <span style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
      <span
        style={{
          width: 8,
          height: 8,
          borderRadius: "50%",
          background: ok ? "var(--status-success)" : "var(--status-fail)",
          display: "inline-block",
        }}
      />
      <span style={{ color: ok ? "var(--status-success)" : "var(--status-fail)" }}>
        {ok ? okText : badText}
      </span>
    </span>
  );
}

function CircuitBreaker({ status }) {
  if (!status || status.error) {
    return <StatusLine ok={false} badText={status?.error || "Unknown"} />;
  }
  // gemini_rotation.get_circuit_breaker_status() returns a dict keyed by
  // model name -> {state: CLOSED|OPEN|HALF_OPEN, ...}. Render per-model
  // so one bad model doesn't hide behind an aggregate "OK".
  const entries = Object.entries(status);
  if (entries.length === 0) {
    return <span style={{ fontSize: 12, color: "var(--text-muted)" }}>No models tracked yet</span>;
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
      {entries.map(([model, info]) => {
        const state = typeof info === "object" ? info.state : info;
        const color =
          state === "OPEN" ? "var(--status-fail)" : state === "HALF_OPEN" ? "var(--sev-medium)" : "var(--status-success)";
        return (
          <div key={model} style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
            <span className="mono">{model}</span>
            <span style={{ color }}>{state}</span>
          </div>
        );
      })}
    </div>
  );
}
