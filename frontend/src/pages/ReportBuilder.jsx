/**
 * ReportBuilder.jsx - turns one triaged finding into a submission-ready
 * report. Pulls a structured starting draft from the backend (title,
 * summary, steps, impact, remediation, evidence - assembled from what
 * triage already collected), then the operator edits every field
 * before copying or downloading. One finding per report, on purpose -
 * that's how Bugcrowd/HackerOne actually want submissions, unlike the
 * whole-project dump report.
 */
import { useEffect, useState } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { api } from "../api/client";
import { SeverityBadge } from "../components/FindingsList";
import { platformLabel } from "../constants";

function buildMarkdown(draft) {
  const lines = [
    `# ${draft.title}`,
    "",
    `**Severity:** ${draft.severity}  `,
    `**Target:** \`${draft.target}\`  `,
    `**Found via:** ${draft.tool_name}`,
    "",
    "## Summary",
    "",
    draft.summary,
    "",
    "## Steps to Reproduce",
    "",
    draft.steps_to_reproduce,
    "",
    "## Impact",
    "",
    draft.impact,
    "",
    "## Remediation",
    "",
    draft.remediation,
  ];
  if (draft.evidence) {
    lines.push("", "## Evidence", "", "```", draft.evidence.trim(), "```");
  }
  return lines.join("\n");
}

function Field({ label, value, onChange, rows = 3 }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <label className="eyebrow" style={{ display: "block", marginBottom: 5 }}>
        {label}
      </label>
      <textarea
        className="input"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        rows={rows}
        style={{ width: "100%", fontFamily: "var(--font-ui)", fontSize: 13, lineHeight: 1.5, resize: "vertical" }}
      />
    </div>
  );
}

export function ReportBuilder() {
  const { findingId } = useParams();
  const navigate = useNavigate();
  const [draft, setDraft] = useState(null);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    api.getReportDraft(findingId).then(setDraft).catch((err) => setError(err.message));
  }, [findingId]);

  function update(field, value) {
    setDraft((d) => ({ ...d, [field]: value }));
  }

  async function handleCopy() {
    await navigator.clipboard.writeText(buildMarkdown(draft));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  function handleDownload() {
    const blob = new Blob([buildMarkdown(draft)], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const safeName = draft.title.toLowerCase().replace(/[^a-z0-9]+/g, "_").slice(0, 60);
    a.href = url;
    a.download = `report_${safeName}_${draft.finding_id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  if (error) return <p style={{ color: "var(--status-fail)" }}>Couldn't load draft: {error}</p>;
  if (draft === null) return <p style={{ color: "var(--text-muted)" }}>Loading…</p>;

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 14, flexWrap: "wrap", gap: 10 }}>
        <div>
          <button className="btn" onClick={() => navigate(-1)} style={{ marginBottom: 8, padding: "3px 9px", fontSize: 11 }}>
            ← Back
          </button>
          <div className="eyebrow" style={{ marginBottom: 4 }}>Report draft</div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <h1 style={{ fontSize: 20, fontWeight: 500, margin: 0 }}>{draft.vuln_type}</h1>
            <SeverityBadge severity={draft.severity} />
          </div>
          <Link to={`/projects/${draft.project_id}`} style={{ fontSize: 12, color: "var(--text-secondary)" }}>
            {draft.project_name} ({platformLabel(draft.platform)}) →
          </Link>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn" onClick={handleCopy}>
            {copied ? "Copied!" : "Copy Markdown"}
          </button>
          <button className="btn btn-primary" onClick={handleDownload}>
            Download .md
          </button>
        </div>
      </div>

      <div style={{ display: "flex", gap: 16, flex: 1, minHeight: 0 }}>
        <div className="ops-panel" data-label="Edit" style={{ flex: 1, minWidth: 0, overflowY: "auto", padding: "18px 20px" }}>
          <Field label="Title" value={draft.title} onChange={(v) => update("title", v)} rows={1} />
          <Field label="Summary" value={draft.summary} onChange={(v) => update("summary", v)} rows={3} />
          <Field label="Steps to Reproduce" value={draft.steps_to_reproduce} onChange={(v) => update("steps_to_reproduce", v)} rows={6} />
          <Field label="Impact" value={draft.impact} onChange={(v) => update("impact", v)} rows={3} />
          <Field label="Remediation" value={draft.remediation} onChange={(v) => update("remediation", v)} rows={3} />
          {draft.evidence && (
            <div>
              <label className="eyebrow" style={{ display: "block", marginBottom: 5 }}>
                Evidence (from scan, read-only)
              </label>
              <pre
                className="mono"
                style={{
                  background: "var(--bg-canvas)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius)",
                  padding: 12,
                  fontSize: 12,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                  maxHeight: 220,
                  overflowY: "auto",
                }}
              >
                {draft.evidence}
              </pre>
            </div>
          )}
        </div>

        <div className="ops-panel" data-label="Preview" style={{ flex: 1, minWidth: 0, overflowY: "auto", padding: "18px 20px" }}>
          <pre
            className="mono"
            style={{ whiteSpace: "pre-wrap", wordBreak: "break-word", fontSize: 12.5, lineHeight: 1.6, margin: 0 }}
          >
            {buildMarkdown(draft)}
          </pre>
        </div>
      </div>
    </div>
  );
}
