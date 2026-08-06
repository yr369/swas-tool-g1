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
import { Link } from "react-router-dom";
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
  const trippedModels =
    data.ai.circuit_breaker && !data.ai.circuit_breaker.error ? Object.keys(data.ai.circuit_breaker).length : 0;

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

        <Panel label="AI ROTATION" accent={trippedModels > 0 ? "var(--status-fail)" : undefined}>
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
                <div key={r.kind} style={{ display: "flex", flexDirection: "column", fontSize: 12 }}>
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span className="mono">{r.kind}</span>
                    <span style={{ color: r.pending > 0 ? "var(--sev-medium)" : "var(--text-muted)" }}>
                      {r.pending} pending{r.failed_24h > 0 ? `, ${r.failed_24h} failed/24h` : ""}
                    </span>
                  </div>
                  {r.oldest_pending_due_at && (
                    <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                      next auto-retry {new Date(r.oldest_pending_due_at).toLocaleTimeString()}
                    </span>
                  )}
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
                  <Link to={`/projects/${c.project_id}`} style={{ color: "var(--text-primary)" }}>
                    {c.project_name}
                  </Link>
                  <span style={{ color: c.drifted ? "var(--status-fail)" : "var(--status-success)" }}>
                    {c.current_finding_count} / baseline {c.baseline_finding_count ?? "—"}
                  </span>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel label="OUTCOMES AWAITING" accent={data.outcomes_awaiting_total > 0 ? "var(--sev-medium)" : undefined}>
          {data.outcomes_awaiting_total === 0 ? (
            <StatusLine ok okText="All caught up" />
          ) : (
            <span style={{ fontSize: 12, color: "var(--sev-medium)" }}>
              {data.outcomes_awaiting_total} submitted finding{data.outcomes_awaiting_total === 1 ? "" : "s"} with no
              logged result yet
            </span>
          )}
        </Panel>
      </div>

      {data.evidence.dead_targets.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <div
            className="ops-panel"
            data-label={
              data.evidence.dead_targets_total > data.evidence.dead_targets.length
                ? `DEAD TARGETS · ${data.evidence.dead_targets_total} (showing ${data.evidence.dead_targets.length})`
                : `DEAD TARGETS · ${data.evidence.dead_targets_total}`
            }
            style={{ overflow: "hidden" }}
          >
            {data.evidence.dead_targets.map((t, i) => (
              <Link
                key={t.target_id}
                to={`/projects/${t.project_id}`}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  padding: "10px 16px",
                  borderBottom: i < data.evidence.dead_targets.length - 1 ? "1px solid var(--border)" : "none",
                  fontSize: 12,
                  textDecoration: "none",
                  color: "inherit",
                }}
              >
                <div>
                  <span className="mono">{t.target}</span>
                  <span style={{ color: "var(--text-muted)", marginLeft: 8 }}>({t.project_name})</span>
                </div>
                <span style={{ color: "var(--text-muted)" }}>
                  {t.dead_since ? `dark since ${new Date(t.dead_since).toLocaleDateString()}` : ""}
                </span>
              </Link>
            ))}
          </div>
        </div>
      )}

      {data.outcomes_awaiting.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <div
            className="ops-panel"
            data-label={
              data.outcomes_awaiting_total > data.outcomes_awaiting.length
                ? `OUTCOMES AWAITING · ${data.outcomes_awaiting_total} (showing oldest ${data.outcomes_awaiting.length})`
                : `OUTCOMES AWAITING · ${data.outcomes_awaiting_total}`
            }
            style={{ overflow: "hidden" }}
          >
            {data.outcomes_awaiting.map((o, i) => (
              <Link
                key={o.finding_id}
                to={`/projects/${o.project_id}`}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  padding: "10px 16px",
                  borderBottom: i < data.outcomes_awaiting.length - 1 ? "1px solid var(--border)" : "none",
                  fontSize: 12,
                  textDecoration: "none",
                  color: "inherit",
                }}
              >
                <div>
                  <span className="mono">{o.vuln_type || "(untyped finding)"}</span>
                  <span style={{ color: "var(--text-muted)", marginLeft: 8 }}>({o.project_name})</span>
                </div>
                <span style={{ color: "var(--text-muted)" }}>
                  {o.submitted_since ? `since ${new Date(o.submitted_since).toLocaleDateString()}` : ""}
                </span>
              </Link>
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
  // gemini_rotation.get_circuit_breaker_status() returns
  // {model: secondsRemainingInCooldown} - a plain number, and ONLY for
  // models that are CURRENTLY tripped (healthy models never appear in
  // this dict at all). Every key present here is by definition tripped
  // - there's no per-model "state" field to read, and an empty dict
  // means every model is healthy, not "no data yet".
  const entries = Object.entries(status);
  if (entries.length === 0) {
    return <StatusLine ok okText="All models healthy" />;
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
      {entries.map(([model, secondsRemaining]) => (
        <div key={model} style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
          <span className="mono">{model}</span>
          <span style={{ color: "var(--status-fail)" }}>
            cooling down · {Math.ceil(secondsRemaining)}s left
          </span>
        </div>
      ))}
    </div>
  );
}
