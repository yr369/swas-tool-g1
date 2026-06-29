/**
 * ScopeIntake.jsx - the two-step scope intake flow.
 *
 * Step 1: operator pastes text or uploads a file -> sent to the backend's
 *         Gemini-powered parser -> a PREVIEW comes back. Nothing is saved
 *         to the database yet at this point.
 * Step 2: operator reviews the preview (can edit target_type/in_scope
 *         inline before confirming) -> confirms -> THIS is what actually
 *         creates the project and saves the scope.
 */

import { useState } from "react";
import { api } from "../api/client";

const TARGET_TYPES = ["website", "api", "mobile", "hardware", "unknown"];

export function ScopeIntake({ onProjectCreated }) {
  const [platform, setPlatform] = useState("bugcrowd");
  const [projectName, setProjectName] = useState("");
  const [rawText, setRawText] = useState("");
  const [preview, setPreview] = useState(null); // null = not parsed yet
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function handleParse() {
    setError(null);
    setLoading(true);
    try {
      const result = await api.parseScopeText(platform, rawText);
      setPreview(result.items);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function updateItem(index, field, value) {
    setPreview((items) => items.map((item, i) => (i === index ? { ...item, [field]: value } : item)));
  }

  async function handleConfirm() {
    if (!projectName.trim()) {
      setError("Name this project before saving.");
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const project = await api.confirmScope({
        project_name: projectName,
        platform,
        items: preview,
      });
      onProjectCreated(project);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  if (preview) {
    return (
      <div>
        <h2 style={{ fontSize: 16, fontWeight: 600, margin: "0 0 4px" }}>Review scope</h2>
        <p style={{ color: "var(--text-muted)", fontSize: 13, margin: "0 0 16px" }}>
          Check every target before saving. Mobile app IDs are flagged for review, not silently dropped.
        </p>

        <div style={{ marginBottom: 16 }}>
          <input
            type="text"
            placeholder="Project name"
            value={projectName}
            onChange={(e) => setProjectName(e.target.value)}
            style={inputStyle}
          />
        </div>

        <div style={{ border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", overflow: "hidden", marginBottom: 16 }}>
          {preview.map((item, i) => (
            <div
              key={i}
              style={{
                display: "flex",
                gap: 12,
                padding: "10px 14px",
                borderBottom: i < preview.length - 1 ? "1px solid var(--border)" : "none",
                alignItems: "center",
              }}
            >
              <span className="mono" style={{ flex: 1, fontSize: 13 }}>
                {item.target}
              </span>
              <select
                value={item.target_type}
                onChange={(e) => updateItem(i, "target_type", e.target.value)}
                style={{ ...selectStyle, width: 110 }}
              >
                {TARGET_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
              <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13, color: "var(--text-secondary)" }}>
                <input
                  type="checkbox"
                  checked={item.in_scope}
                  onChange={(e) => updateItem(i, "in_scope", e.target.checked)}
                />
                In scope
              </label>
            </div>
          ))}
        </div>

        {error && <p style={{ color: "var(--status-fail)", fontSize: 13 }}>{error}</p>}

        <div style={{ display: "flex", gap: 8 }}>
          <button onClick={() => setPreview(null)} style={secondaryButtonStyle}>
            Back
          </button>
          <button onClick={handleConfirm} disabled={loading} style={primaryButtonStyle}>
            {loading ? "Saving…" : "Save and create project"}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div>
      <h2 style={{ fontSize: 16, fontWeight: 600, margin: "0 0 4px" }}>New project</h2>
      <p style={{ color: "var(--text-muted)", fontSize: 13, margin: "0 0 16px" }}>
        Paste the program's scope text below. It'll be parsed automatically - you'll review every target before anything is saved.
      </p>

      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        {["bugcrowd", "hackerone"].map((p) => (
          <button
            key={p}
            onClick={() => setPlatform(p)}
            style={{
              ...secondaryButtonStyle,
              borderColor: platform === p ? "var(--accent)" : "var(--border)",
              color: platform === p ? "var(--accent)" : "var(--text-secondary)",
            }}
          >
            {p === "bugcrowd" ? "Bugcrowd" : "HackerOne"}
          </button>
        ))}
      </div>

      <textarea
        value={rawText}
        onChange={(e) => setRawText(e.target.value)}
        placeholder="example.com and all subdomains are in scope. api.example.com is in scope, rewards $100-$500. internal.example.com is out of scope."
        rows={8}
        style={{ ...inputStyle, fontFamily: "var(--font-mono)", fontSize: 13, resize: "vertical" }}
      />

      {error && <p style={{ color: "var(--status-fail)", fontSize: 13, marginTop: 8 }}>{error}</p>}

      <div style={{ marginTop: 12 }}>
        <button onClick={handleParse} disabled={loading || !rawText.trim()} style={primaryButtonStyle}>
          {loading ? "Parsing…" : "Parse scope"}
        </button>
      </div>
    </div>
  );
}

const inputStyle = {
  width: "100%",
  background: "var(--bg-surface-raised)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
  color: "var(--text-primary)",
  padding: "8px 12px",
  fontSize: 14,
  fontFamily: "var(--font-ui)",
};

const selectStyle = {
  ...inputStyle,
  padding: "4px 8px",
  fontSize: 13,
};

const primaryButtonStyle = {
  background: "var(--accent)",
  color: "var(--on-accent)",
  border: "none",
  borderRadius: "var(--radius)",
  padding: "8px 16px",
  fontSize: 14,
  fontWeight: 500,
  cursor: "pointer",
};

const secondaryButtonStyle = {
  background: "transparent",
  color: "var(--text-secondary)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
  padding: "8px 16px",
  fontSize: 14,
  cursor: "pointer",
};
