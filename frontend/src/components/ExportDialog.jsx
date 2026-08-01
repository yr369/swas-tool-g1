/**
 * ExportDialog.jsx - "Export" button that opens a panel to pick format
 * (Markdown report or CSV) and narrow exactly which findings go into
 * it, by severity / tool / bug type. Nothing is exported until the
 * operator explicitly picks a format and hits Export - unlike the old
 * always-on links, an unopened dialog exports nothing.
 */

import { useState } from "react";
import { api } from "../api/client";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"];
const SEVERITY_LABEL = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
  unknown: "Note", // "unknown" severity in the DB, "Note" is how findings without a real severity read to a human
};

function CheckboxGroup({ title, options, labelFor, selected, onToggle, onSelectAll, onSelectNone }) {
  if (options.length === 0) return null;
  return (
    <div style={{ marginBottom: 14 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
        <span style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: 0.5, color: "var(--text-muted)" }}>
          {title}
        </span>
        <span style={{ display: "flex", gap: 8 }}>
          <button type="button" onClick={onSelectAll} style={linkButtonStyle}>
            all
          </button>
          <button type="button" onClick={onSelectNone} style={linkButtonStyle}>
            none
          </button>
        </span>
      </div>
      <div
        style={{
          display: "flex", flexDirection: "column", gap: 4, maxHeight: 140, overflowY: "auto",
          border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "6px 8px",
        }}
      >
        {options.map((opt) => (
          <label key={opt} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, cursor: "pointer" }}>
            <input type="checkbox" checked={selected.has(opt)} onChange={() => onToggle(opt)} />
            {labelFor ? labelFor(opt) : opt}
          </label>
        ))}
      </div>
    </div>
  );
}

export function ExportDialog({ projectId, tools, vulnTypes, defaultSeverities }) {
  const [open, setOpen] = useState(false);
  const [format, setFormat] = useState("md");
  const [severities, setSeverities] = useState(() => new Set(defaultSeverities ?? SEVERITY_ORDER.filter((s) => s !== "info" && s !== "unknown")));
  const [selectedTools, setSelectedTools] = useState(() => new Set(tools));
  const [selectedVulnTypes, setSelectedVulnTypes] = useState(() => new Set(vulnTypes));

  function toggle(setFn, value) {
    setFn((prev) => {
      const next = new Set(prev);
      if (next.has(value)) next.delete(value);
      else next.add(value);
      return next;
    });
  }

  function handleExport() {
    if (severities.size === 0) {
      alert("Select at least one severity to export."); // eslint-disable-line no-alert -- simple enough not to need a toast system
      return;
    }
    const filters = {
      severities: [...severities],
      // Only send tools/vulnTypes filters if something was deselected -
      // "everything selected" and "no filter" produce the same export,
      // and omitting the param when nothing was excluded keeps the URL
      // short and matches what a fresh dialog would export by default.
      tools: selectedTools.size < tools.length ? [...selectedTools] : undefined,
      vulnTypes: selectedVulnTypes.size < vulnTypes.length ? [...selectedVulnTypes] : undefined,
    };
    const url = format === "md" ? api.reportUrl(projectId, filters) : api.exportFindingsUrl(projectId, filters);
    window.open(url, "_blank");
    setOpen(false);
  }

  return (
    <div style={{ position: "relative" }}>
      <button type="button" onClick={() => setOpen((v) => !v)} style={smallButtonStyle}>
        Export ▾
      </button>
      {open && (
        <>
          {/* click-outside catcher */}
          <div style={{ position: "fixed", inset: 0, zIndex: 9 }} onClick={() => setOpen(false)} />
          <div
            style={{
              position: "absolute", right: 0, top: "calc(100% + 6px)", zIndex: 10, width: 280,
              background: "var(--bg-surface-raised)", border: "1px solid var(--border)",
              borderRadius: "var(--radius)", padding: 14, boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
            }}
          >
            <div style={{ marginBottom: 14 }}>
              <span style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: 0.5, color: "var(--text-muted)" }}>
                Format
              </span>
              <div style={{ display: "flex", gap: 12, marginTop: 6 }}>
                <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, cursor: "pointer" }}>
                  <input type="radio" name="export-format" checked={format === "md"} onChange={() => setFormat("md")} />
                  Markdown report
                </label>
                <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, cursor: "pointer" }}>
                  <input type="radio" name="export-format" checked={format === "csv"} onChange={() => setFormat("csv")} />
                  CSV
                </label>
              </div>
            </div>

            <CheckboxGroup
              title="Severity"
              options={SEVERITY_ORDER}
              labelFor={(s) => SEVERITY_LABEL[s]}
              selected={severities}
              onToggle={(s) => toggle(setSeverities, s)}
              onSelectAll={() => setSeverities(new Set(SEVERITY_ORDER))}
              onSelectNone={() => setSeverities(new Set())}
            />
            <CheckboxGroup
              title="Tool"
              options={tools}
              selected={selectedTools}
              onToggle={(t) => toggle(setSelectedTools, t)}
              onSelectAll={() => setSelectedTools(new Set(tools))}
              onSelectNone={() => setSelectedTools(new Set())}
            />
            <CheckboxGroup
              title="Bug type"
              options={vulnTypes}
              selected={selectedVulnTypes}
              onToggle={(v) => toggle(setSelectedVulnTypes, v)}
              onSelectAll={() => setSelectedVulnTypes(new Set(vulnTypes))}
              onSelectNone={() => setSelectedVulnTypes(new Set())}
            />

            <button
              type="button"
              onClick={handleExport}
              style={{ ...smallButtonStyle, width: "100%", background: "var(--accent)", color: "var(--bg-base)", marginTop: 4 }}
            >
              Export
            </button>
          </div>
        </>
      )}
    </div>
  );
}

const smallButtonStyle = {
  background: "transparent",
  color: "var(--accent)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
  padding: "5px 10px",
  fontSize: 12,
  cursor: "pointer",
};

const linkButtonStyle = {
  background: "transparent",
  border: "none",
  color: "var(--accent)",
  fontSize: 11,
  cursor: "pointer",
  padding: 0,
};
