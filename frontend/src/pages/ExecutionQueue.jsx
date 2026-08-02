import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";

// Only one project ever runs at a time (see backend _run_due_queue_item) -
// this page polls rather than opening a socket because queue turnover is
// already driven by a 10s server-side worker tick; a 5s poll here never
// falls meaningfully behind that.
const POLL_INTERVAL_MS = 5000;
const REORDER_ANIM_MS = 240;

export function ExecutionQueue() {
  const [items, setItems] = useState(null);
  const [error, setError] = useState(null);
  const [busyId, setBusyId] = useState(null);

  function load() {
    return api
      .listQueue()
      .then((data) => setItems(sortQueue(data)))
      .catch((err) => setError(err.message));
  }

  useEffect(() => {
    load();
    const t = setInterval(load, POLL_INTERVAL_MS);
    return () => clearInterval(t);
  }, []);

  async function move(item, direction) {
    // direction: -1 = up, +1 = down. position is 1-indexed within the
    // 'queued' lane and always sequential (backend renumbers 1..N on
    // every reorder), so shifting one slot is just position ± 1.
    const newPosition = item.position + direction;
    setBusyId(item.id);
    setError(null);
    // Optimistic local reorder so the animation has something to animate
    // toward immediately, rather than waiting on the round trip.
    setItems((prev) => {
      const next = [...prev];
      const i = next.findIndex((x) => x.id === item.id);
      const j = i + direction;
      if (i < 0 || j < 0 || j >= next.length) return prev;
      // never swap across the running item - it isn't reorderable and
      // shouldn't move as a side effect of a neighbor moving
      if (next[i].status !== "queued" || next[j].status !== "queued") return prev;
      [next[i], next[j]] = [next[j], next[i]];
      return next;
    });
    try {
      await api.reorderQueueItem(item.id, newPosition);
      await load();
    } catch (err) {
      setError(err.message);
      await load(); // resync with the server's actual order on failure
    } finally {
      setBusyId(null);
    }
  }

  async function handleRemove(item) {
    setBusyId(item.id);
    setError(null);
    try {
      await api.cancelQueueItem(item.id);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyId(null);
    }
  }

  if (error && items === null) {
    return <p style={{ color: "var(--status-fail)" }}>Couldn't load the execution queue: {error}</p>;
  }
  if (items === null) {
    return <p style={{ color: "var(--text-muted)" }}>Loading…</p>;
  }

  const waiting = items.filter((i) => i.status === "queued");
  const running = items.find((i) => i.status === "running");

  return (
    <div>
      <div className="eyebrow" style={{ marginBottom: 4 }}>Serial execution — one project at a time</div>
      <h1 style={{ fontSize: 24, fontWeight: 500, margin: "0 0 20px" }}>Execution queue</h1>

      {error && (
        <p style={{ color: "var(--status-fail)", fontSize: 13, marginTop: 0 }}>{error}</p>
      )}

      {items.length === 0 ? (
        <div style={{ padding: "48px 16px", textAlign: "center", color: "var(--text-muted)" }}>
          Nothing queued. Use "Add to Execution Queue" on a project to line it up here.
        </div>
      ) : (
        <AnimatedList items={items}>
          {items.map((item, index) => (
            <QueueRow
              key={item.id}
              item={item}
              displayNumber={index + 1}
              canMoveUp={item.status === "queued" && waiting[0]?.id !== item.id}
              canMoveDown={item.status === "queued" && waiting[waiting.length - 1]?.id !== item.id}
              busy={busyId === item.id}
              onUp={() => move(item, -1)}
              onDown={() => move(item, 1)}
              onRemove={() => handleRemove(item)}
            />
          ))}
        </AnimatedList>
      )}
      {!running && waiting.length > 0 && (
        <p style={{ color: "var(--text-muted)", fontSize: 12, marginTop: 12 }}>
          Nothing currently running — the queue worker checks every 10s and will start the top item shortly.
        </p>
      )}
    </div>
  );
}

function sortQueue(data) {
  // Running first, then queued lanes in the order the server will
  // actually process them (priority lane fully drained first, each
  // lane FIFO by position) - GET /api/queue already returns this order,
  // this just guards against relying on fetch-order accidentally.
  return [...data].sort((a, b) => {
    if (a.status !== b.status) return a.status === "running" ? -1 : b.status === "running" ? 1 : 0;
    if (a.priority !== b.priority) return a.priority ? -1 : 1;
    return a.position - b.position;
  });
}

/**
 * FLIP (First-Last-Invert-Play) reorder animation with zero extra
 * dependencies. Before each render caused by `items` changing identity,
 * every row's on-screen position is remembered; after the DOM updates to
 * the new order, each row is snapped back to where it used to be with a
 * transform, then transitioned to translateY(0) - so a reorder always
 * reads as a slide, never a jump cut.
 */
function AnimatedList({ items, children }) {
  const nodeRefs = useRef(new Map());
  const prevRects = useRef(new Map());

  useLayoutEffect(() => {
    const nextRects = new Map();
    nodeRefs.current.forEach((el, id) => {
      if (el) nextRects.set(id, el.getBoundingClientRect());
    });

    nodeRefs.current.forEach((el, id) => {
      if (!el) return;
      const prev = prevRects.current.get(id);
      const next = nextRects.get(id);
      if (!prev || !next) return;
      const deltaY = prev.top - next.top;
      if (Math.abs(deltaY) < 1) return;
      el.style.transition = "none";
      el.style.transform = `translateY(${deltaY}px)`;
      // Force a reflow so the browser registers the starting transform
      // before we switch it to a transitioned one below.
      // eslint-disable-next-line no-unused-expressions
      el.offsetHeight;
      el.style.transition = `transform ${REORDER_ANIM_MS}ms ease`;
      el.style.transform = "";
    });

    prevRects.current = nextRects;
  }, [items]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {items.map((item, i) => (
        <div
          key={item.id}
          ref={(el) => {
            if (el) nodeRefs.current.set(item.id, el);
            else nodeRefs.current.delete(item.id);
          }}
        >
          {children[i]}
        </div>
      ))}
    </div>
  );
}

function QueueRow({ item, displayNumber, canMoveUp, canMoveDown, busy, onUp, onDown, onRemove }) {
  const isRunning = item.status === "running";
  return (
    <div
      className="ops-panel"
      style={{
        padding: "12px 16px",
        display: "flex",
        alignItems: "center",
        gap: 14,
        opacity: busy ? 0.6 : 1,
      }}
    >
      <span
        className="mono"
        style={{
          width: 26,
          height: 26,
          flexShrink: 0,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          borderRadius: "50%",
          border: `1px solid ${isRunning ? "var(--signal)" : "var(--border-strong)"}`,
          color: isRunning ? "var(--signal)" : "var(--text-secondary)",
          fontSize: 12,
        }}
      >
        {displayNumber}
      </span>

      <div style={{ flex: 1, minWidth: 0 }}>
        <Link
          to={`/projects/${item.project_id}`}
          style={{ color: "var(--text-primary)", fontWeight: 500, textDecoration: "none" }}
        >
          {item.project_name}
        </Link>
        <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>
          {isRunning ? (
            <span style={{ color: "var(--signal)", display: "inline-flex", alignItems: "center", gap: 6 }}>
              <span
                aria-hidden="true"
                style={{
                  width: 6,
                  height: 6,
                  borderRadius: "50%",
                  background: "var(--signal)",
                  animation: "signal-pulse 1.6s ease-out infinite",
                }}
              />
              Currently running
            </span>
          ) : (
            <>
              Waiting{item.priority ? " · priority" : ""}
              {item.estimated_start_at && <> · est. start {formatTime(item.estimated_start_at)}</>}
            </>
          )}
        </div>
      </div>

      {!isRunning && (
        <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
          <button
            className="btn"
            onClick={onUp}
            disabled={!canMoveUp || busy}
            title="Move up"
            style={{ padding: "5px 9px", fontSize: 12, minWidth: "auto" }}
          >
            ↑
          </button>
          <button
            className="btn"
            onClick={onDown}
            disabled={!canMoveDown || busy}
            title="Move down"
            style={{ padding: "5px 9px", fontSize: 12, minWidth: "auto" }}
          >
            ↓
          </button>
          <button
            className="btn"
            onClick={onRemove}
            disabled={busy}
            title="Remove from queue"
            style={{ padding: "5px 9px", fontSize: 12, minWidth: "auto", color: "var(--status-fail)" }}
          >
            ✕
          </button>
        </div>
      )}
    </div>
  );
}

function formatTime(isoString) {
  return new Date(isoString).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}
