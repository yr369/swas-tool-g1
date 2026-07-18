import { useMemo, useState } from "react";
import { api } from "../api/client";

/**
 * ScanNotesPanel.jsx - "more valid bugs" pass, item 3 of 3.
 *
 * Detective checks that are deliberately NOT auto-filed as findings
 * (unconfirmed pattern matches needing manual review, or confirmed
 * gaps that are almost always Informative alone - see each check's own
 * docstring in detective.py and add_scan_notes.sql) used to just get
 * logged to the backend container and discarded. This panel is what
 * actually surfaces them - kept visually distinct from FindingsList so
 * it's clear these are unverified signal, not graded findings.
 */
export function ScanNotesPanel({ projectId, notes, onDismissed }) {
  const [dismissing, setDismissing] = useState(null);
  const [expanded, setExpanded] = useState(false);

  const grouped = useMemo(() => {
    const map = new Map();
    for (const n of notes) {
      if (!map.has(n.check_name)) map.set(n.check_name, []);
      map.get(n.check_name).push(n);
    }
    return [...map.entries()].sort((a, b) => b[1].length - a[1].length);
  }, [notes]);

  async function handleDismiss(noteId) {
    setDismissing(noteId);
    try {
      await api.dismissScanNote(noteId);
      onDismissed?.();
    } catch (err) {
      console.error(err);
    } finally {
      setDismissing(null);
    }
  }

  if (notes.length === 0) return null;

  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", overflow: "hidden" }}>
      <button
        onClick={() => setExpanded((e) => !e)}
        style={{
          width: "100%", display: "flex", justifyContent: "space-between", alignItems: "center",
          padding: "12px 16px", background: "var(--bg-surface-raised)", border: "none",
          color: "var(--text-primary)", fontSize: 13, cursor: "pointer", textAlign: "left",
        }}
      >
        <span>
          {notes.length} note{notes.length === 1 ? "" : "s"} for manual review — unconfirmed pattern matches and
          low-value-alone gaps detective.py deliberately doesn't auto-file as findings
        </span>
        <span className="mono" style={{ color: "var(--text-muted)" }}>{expanded ? "▲" : "▼"}</span>
      </button>

      {expanded && (
        <div>
          {grouped.map(([checkName, group]) => (
            <div key={checkName} style={{ borderTop: "1px solid var(--border)" }}>
              <div style={{ padding: "8px 16px", fontSize: 11, color: "var(--text-muted)" }} className="mono">
                {checkName} · {group.length}
              </div>
              {group.map((n) => (
                <div
                  key={n.id}
                  style={{
                    display: "flex", gap: 12, alignItems: "flex-start",
                    padding: "6px 16px 10px", borderTop: "1px solid var(--border)",
                  }}
                >
                  <pre
                    className="mono"
                    style={{ flex: 1, minWidth: 0, margin: 0, fontSize: 12, color: "var(--text-secondary)", whiteSpace: "pre-wrap", wordBreak: "break-word" }}
                  >
                    {n.note}
                  </pre>
                  <button
                    onClick={() => handleDismiss(n.id)}
                    disabled={dismissing === n.id}
                    style={{
                      background: "transparent", border: "1px solid var(--border)", borderRadius: "var(--radius)",
                      color: "var(--text-muted)", fontSize: 11, padding: "3px 8px", cursor: "pointer", whiteSpace: "nowrap",
                    }}
                  >
                    {dismissing === n.id ? "…" : "Dismiss"}
                  </button>
                </div>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
