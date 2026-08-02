const GROUPS = [
  {
    title: "Navigate",
    items: [
      ["G then P", "Projects"],
      ["G then H", "Chronology"],
      ["G then Q", "Execution queue"],
      ["G then T", "Triage queue"],
      ["G then D", "Dashboard"],
      ["G then O", "System"],
      ["G then C", "Scheduled scans"],
      ["G then S", "Signature stats"],
      ["G then N", "New project"],
    ],
  },
  {
    title: "In the triage queue",
    items: [
      ["J / K", "Next / previous finding"],
      ["A", "Accept (mark reviewed)"],
      ["R", "Reject (dismiss)"],
      ["S", "Mark submitted"],
    ],
  },
  {
    title: "Global",
    items: [
      ["⌘K / Ctrl K", "Command palette"],
      ["[", "Collapse / expand sidebar"],
      ["?", "This reference"],
      ["Esc", "Close dialog"],
    ],
  },
];

export function ShortcutsModal({ onClose }) {
  return (
    <div
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(6, 9, 7, 0.7)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 100,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="ops-panel"
        data-label="KEYBIND REFERENCE"
        style={{ width: 420, maxWidth: "90vw", padding: "28px 22px 20px", background: "var(--bg-surface-raised)" }}
      >
        {GROUPS.map((g) => (
          <div key={g.title} style={{ marginBottom: 18 }}>
            <div className="eyebrow" style={{ marginBottom: 8 }}>
              {g.title}
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {g.items.map(([keys, label]) => (
                <div key={label} style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontSize: 13, color: "var(--text-secondary)" }}>{label}</span>
                  <span className="kbd" style={{ minWidth: "auto", padding: "2px 8px" }}>
                    {keys}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ))}
        <button className="btn" onClick={onClose} style={{ width: "100%", justifyContent: "center" }}>
          CLOSE
        </button>
      </div>
    </div>
  );
}
