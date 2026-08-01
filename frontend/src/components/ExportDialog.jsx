/**
 * ExportDialog.jsx - "Export" button that walks through a step wizard
 * before generating anything:
 *   1. format (Markdown / CSV)
 *   2. primary sort-by (Tool or Severity)
 *   3. tick which values of that dimension to include
 *   4. secondary sort-by (whichever dimension wasn't picked in step 2)
 *   5. tick which values of THAT dimension to include
 * Both tick-sets are ANDed together server-side - e.g. severity in
 * {critical, high} AND tool in {nuclei, sqlmap}. Nothing is generated
 * until the final step's Export button is pressed.
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
  unknown: "Note", // "unknown" severity in the DB - findings with no real severity yet read as "Note" to a human
};

const STEPS = ["format", "primaryDim", "primaryValues", "secondaryDim", "secondaryValues"];

function optionsFor(dimension, tools, vulnTypes) {
  return dimension === "severity" ? SEVERITY_ORDER : dimension === "tool" ? tools : vulnTypes;
}

function labelFor(dimension, value) {
  return dimension === "severity" ? SEVERITY_LABEL[value] : value;
}

function dimensionName(dimension) {
  return dimension === "severity" ? "Severity" : dimension === "tool" ? "Tool" : "Bug type";
}

export function ExportDialog({ projectId, tools, vulnTypes }) {
  const [open, setOpen] = useState(false);
  const [stepIdx, setStepIdx] = useState(0);
  const [format, setFormat] = useState("csv");
  const [primaryDim, setPrimaryDim] = useState("severity");
  const [primaryValues, setPrimaryValues] = useState(new Set());
  const [secondaryDim, setSecondaryDim] = useState("tool");
  const [secondaryValues, setSecondaryValues] = useState(new Set());

  const step = STEPS[stepIdx];

  function reset() {
    setStepIdx(0);
    setFormat("csv");
    setPrimaryDim("severity");
    setPrimaryValues(new Set());
    setSecondaryDim("tool");
    setSecondaryValues(new Set());
  }

  function close() {
    setOpen(false);
    reset();
  }

  function toggleValue(setFn, value) {
    setFn((prev) => {
      const next = new Set(prev);
      if (next.has(value)) next.delete(value);
      else next.add(value);
      return next;
    });
  }

  function goNext() {
    if (step === "primaryDim") {
      // Secondary dimension is whatever wasn't picked as primary - the
      // remaining two options if primary was "tool" or "severity", but
      // this UI only ever offers tool/severity as the two top-level
      // choices, so secondary is simply the other one of those two.
      setSecondaryDim(primaryDim === "severity" ? "tool" : "severity");
      setPrimaryValues(new Set(optionsFor(primaryDim, tools, vulnTypes)));
    }
    if (step === "secondaryDim") {
      setSecondaryValues(new Set(optionsFor(secondaryDim, tools, vulnTypes)));
    }
    setStepIdx((i) => Math.min(i + 1, STEPS.length - 1));
  }

  function goBack() {
    setStepIdx((i) => Math.max(i - 1, 0));
  }

  function handleExport() {
    if (primaryValues.size === 0 || secondaryValues.size === 0) {
      alert("Tick at least one value in both filter steps."); // eslint-disable-line no-alert -- simple enough not to need a toast system
      return;
    }
    const filters = {
      severities: primaryDim === "severity" ? [...primaryValues] : [...secondaryValues],
      tools: primaryDim === "tool" ? [...primaryValues] : secondaryDim === "tool" ? [...secondaryValues] : undefined,
      vulnTypes: undefined, // bug-type drill-down not offered as a top-level step yet - only tool/severity are
    };
    const url = format === "md" ? api.reportUrl(projectId, filters) : api.exportFindingsUrl(projectId, filters);
    window.open(url, "_blank");
    close();
  }

  return (
    <div style={{ position: "relative" }}>
      <button type="button" onClick={() => setOpen((v) => !v)} style={smallButtonStyle}>
        Export ▾
      </button>
      {open && (
        <>
          <div style={{ position: "fixed", inset: 0, zIndex: 9 }} onClick={close} />
          <div
            style={{
              position: "absolute", right: 0, top: "calc(100% + 6px)", zIndex: 10, width: 300,
              background: "var(--bg-surface-raised)", border: "1px solid var(--border)",
              borderRadius: "var(--radius)", padding: 16, boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
            }}
          >
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 10 }}>
              Step {stepIdx + 1} of {STEPS.length}
            </div>

            {step === "format" && (
              <div>
                <div style={labelStyle}>Format</div>
                <label style={radioRowStyle}>
                  <input type="radio" name="fmt" checked={format === "csv"} onChange={() => setFormat("csv")} />
                  CSV
                </label>
                <label style={radioRowStyle}>
                  <input type="radio" name="fmt" checked={format === "md"} onChange={() => setFormat("md")} />
                  Markdown report
                </label>
              </div>
            )}

            {step === "primaryDim" && (
              <div>
                <div style={labelStyle}>Sort by</div>
                <label style={radioRowStyle}>
                  <input type="radio" name="pdim" checked={primaryDim === "severity"} onChange={() => setPrimaryDim("severity")} />
                  Severity
                </label>
                <label style={radioRowStyle}>
                  <input type="radio" name="pdim" checked={primaryDim === "tool"} onChange={() => setPrimaryDim("tool")} />
                  Tool
                </label>
              </div>
            )}

            {step === "primaryValues" && (
              <ValueChecklist
                title={`Tick ${dimensionName(primaryDim).toLowerCase()} values`}
                options={optionsFor(primaryDim, tools, vulnTypes)}
                dimension={primaryDim}
                selected={primaryValues}
                onToggle={(v) => toggleValue(setPrimaryValues, v)}
                onAll={() => setPrimaryValues(new Set(optionsFor(primaryDim, tools, vulnTypes)))}
                onNone={() => setPrimaryValues(new Set())}
              />
            )}

            {step === "secondaryDim" && (
              <div>
                <div style={labelStyle}>Then further sort by</div>
                <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 4 }}>
                  {dimensionName(secondaryDim)} (the remaining dimension)
                </div>
              </div>
            )}

            {step === "secondaryValues" && (
              <ValueChecklist
                title={`Tick ${dimensionName(secondaryDim).toLowerCase()} values`}
                options={optionsFor(secondaryDim, tools, vulnTypes)}
                dimension={secondaryDim}
                selected={secondaryValues}
                onToggle={(v) => toggleValue(setSecondaryValues, v)}
                onAll={() => setSecondaryValues(new Set(optionsFor(secondaryDim, tools, vulnTypes)))}
                onNone={() => setSecondaryValues(new Set())}
              />
            )}

            <div style={{ display: "flex", gap: 8, marginTop: 14 }}>
              {stepIdx > 0 && (
                <button type="button" onClick={goBack} style={{ ...smallButtonStyle, flex: 1 }}>
                  Back
                </button>
              )}
              {step !== "secondaryValues" ? (
                <button type="button" onClick={goNext} style={{ ...smallButtonStyle, flex: 1 }}>
                  Next
                </button>
              ) : (
                <button
                  type="button"
                  onClick={handleExport}
                  style={{ ...smallButtonStyle, flex: 1, background: "var(--accent)", color: "var(--bg-base)" }}
                >
                  Export
                </button>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function ValueChecklist({ title, options, dimension, selected, onToggle, onAll, onNone }) {
  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
        <span style={labelStyle}>{title}</span>
        <span style={{ display: "flex", gap: 8 }}>
          <button type="button" onClick={onAll} style={linkButtonStyle}>all</button>
          <button type="button" onClick={onNone} style={linkButtonStyle}>none</button>
        </span>
      </div>
      <div
        style={{
          display: "flex", flexDirection: "column", gap: 4, maxHeight: 160, overflowY: "auto",
          border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "6px 8px",
        }}
      >
        {options.length === 0 && <span style={{ fontSize: 12, color: "var(--text-muted)" }}>None available</span>}
        {options.map((opt) => (
          <label key={opt} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, cursor: "pointer" }}>
            <input type="checkbox" checked={selected.has(opt)} onChange={() => onToggle(opt)} />
            {labelFor(dimension, opt)}
          </label>
        ))}
      </div>
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

const labelStyle = {
  fontSize: 11,
  textTransform: "uppercase",
  letterSpacing: 0.5,
  color: "var(--text-muted)",
};

const radioRowStyle = {
  display: "flex",
  alignItems: "center",
  gap: 6,
  fontSize: 13,
  cursor: "pointer",
  padding: "4px 0",
};
