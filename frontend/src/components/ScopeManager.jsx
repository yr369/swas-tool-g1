/**
 * ScopeManager.jsx - the Scope section on the project detail page.
 * Handles editing a target in place, deleting one (with the backend's
 * findings-guard surfaced as a plain message, not a crash), and bulk
 * importing a pasted list of targets sharing one type/in-scope value.
 */

import { useState } from "react";
import { api } from "../api/client";

const TARGET_TYPES = ["website", "api", "mobile", "hardware", "unknown"];

export function ScopeManager({ projectId, scope, onChange }) {
  const [addingBulk, setAddingBulk] = useState(false);

  return (
    <div>
      <div style={{ border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", overflow: "hidden" }}>
        {scope.length === 0 ? (
          <div style={{ padding: 16, color: "var(--text-muted)", fontSize: 13 }}>No targets added yet.</div>
        ) : (
          scope.map((s, i) => (
            <ScopeRow
              key={s.id}
              target={s}
              projectId={projectId}
              isLast={i === scope.length - 1}
              onChange={onChange}
            />
          ))
        )}
      </div>

      <div style={{ marginTop: 12 }}>
        {addingBulk ? (
          <BulkAddForm
            projectId={projectId}
            onDone={() => {
              setAddingBulk(false);
              onChange();
            }}
            onCancel={() => setAddingBulk(false)}
          />
        ) : (
          <button onClick={() => setAddingBulk(true)} style={secondaryButtonStyle}>
            + Bulk import targets
          </button>
        )}
      </div>
    </div>
  );
}

function ScopeRow({ target, projectId, isLast, onChange }) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(target);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState(null);
  const [confirmingDelete, setConfirmingDelete] = useState(false);

  async function handleSave() {
    setSaving(true);
    try {
      await api.updateScopeTarget(projectId, target.id, {
        target: draft.target,
        target_type: draft.target_type,
        in_scope: draft.in_scope,
        notes: draft.notes,
      });
      setEditing(false);
      onChange();
    } catch (err) {
      // Keep the row in edit mode so the person can see what they typed
      // and try again, rather than silently reverting.
      setDeleteError(null);
      alert(err.message); // eslint-disable-line no-alert -- simple enough not to need a toast system
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    setDeleting(true);
    setDeleteError(null);
    try {
      await api.deleteScopeTarget(projectId, target.id);
      onChange();
    } catch (err) {
      // The backend's 409 message already explains exactly why (N
      // findings attached) and what to do instead (set out of scope) -
      // just show it verbatim rather than re-wording it.
      setDeleteError(err.message);
      setConfirmingDelete(false);
    } finally {
      setDeleting(false);
    }
  }

  if (editing) {
    return (
      <div
        style={{
          padding: "10px 14px",
          borderBottom: isLast ? "none" : "1px solid var(--border)",
          display: "flex",
          flexDirection: "column",
          gap: 8,
        }}
      >
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <input
            className="mono"
            value={draft.target}
            onChange={(e) => setDraft({ ...draft, target: e.target.value })}
            style={{ ...inputStyle, flex: 1, minWidth: 160 }}
          />
          <select
            value={draft.target_type}
            onChange={(e) => setDraft({ ...draft, target_type: e.target.value })}
            style={inputStyle}
          >
            {TARGET_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--text-secondary)" }}>
            <input
              type="checkbox"
              checked={draft.in_scope}
              onChange={(e) => setDraft({ ...draft, in_scope: e.target.checked })}
            />
            In scope
          </label>
        </div>
        <input
          placeholder="Notes (optional)"
          value={draft.notes || ""}
          onChange={(e) => setDraft({ ...draft, notes: e.target.value })}
          style={inputStyle}
        />
        <div style={{ display: "flex", gap: 8 }}>
          <button onClick={handleSave} disabled={saving} style={primaryButtonStyle}>
            {saving ? "Saving…" : "Save"}
          </button>
          <button
            onClick={() => {
              setDraft(target);
              setEditing(false);
            }}
            style={secondaryButtonStyle}
          >
            Cancel
          </button>
        </div>
      </div>
    );
  }

  return (
    <div
      style={{
        borderBottom: isLast ? "none" : "1px solid var(--border)",
        opacity: target.in_scope ? 1 : 0.5,
      }}
    >
      <div style={{ display: "flex", gap: 12, alignItems: "center", padding: "10px 14px" }}>
        <span className="mono" style={{ flex: 1, fontSize: 13, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis" }}>
          {target.target}
        </span>
        <span style={{ fontSize: 12, color: "var(--text-muted)" }}>{target.target_type}</span>
        <span style={{ fontSize: 12, color: target.in_scope ? "var(--status-success)" : "var(--text-muted)" }}>
          {target.in_scope ? "In scope" : "Out of scope"}
        </span>
        <button onClick={() => setEditing(true)} style={linkButtonStyle}>
          Edit
        </button>
        {confirmingDelete ? (
          <span style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <span style={{ fontSize: 12, color: "var(--text-muted)" }}>Delete?</span>
            <button onClick={handleDelete} disabled={deleting} style={{ ...linkButtonStyle, color: "var(--status-fail)" }}>
              {deleting ? "…" : "Yes"}
            </button>
            <button onClick={() => setConfirmingDelete(false)} style={linkButtonStyle}>
              No
            </button>
          </span>
        ) : (
          <button onClick={() => setConfirmingDelete(true)} style={{ ...linkButtonStyle, color: "var(--status-fail)" }}>
            Delete
          </button>
        )}
      </div>
      {deleteError && (
        <div style={{ padding: "0 14px 10px", fontSize: 12, color: "var(--sev-medium)" }}>{deleteError}</div>
      )}
    </div>
  );
}

function BulkAddForm({ projectId, onDone, onCancel }) {
  const [text, setText] = useState("");
  const [targetType, setTargetType] = useState("unknown");
  const [inScope, setInScope] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  async function handleSubmit() {
    const targets = text.split("\n").map((l) => l.trim()).filter(Boolean);
    if (targets.length === 0) {
      setError("Paste at least one target, one per line.");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const res = await api.bulkAddScopeTargets(projectId, { targets, target_type: targetType, in_scope: inScope });
      setResult(res);
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  if (result) {
    return (
      <div style={{ border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: 14, fontSize: 13 }}>
        <p style={{ margin: "0 0 4px", color: "var(--status-success)" }}>
          Added {result.created.length} target{result.created.length === 1 ? "" : "s"}.
        </p>
        {result.skipped_duplicates.length > 0 && (
          <p style={{ margin: 0, color: "var(--text-muted)" }}>
            Skipped {result.skipped_duplicates.length} already in scope: {result.skipped_duplicates.join(", ")}
          </p>
        )}
        <button onClick={onDone} style={{ ...secondaryButtonStyle, marginTop: 10 }}>
          Done
        </button>
      </div>
    );
  }

  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: "var(--radius-lg)", padding: 14 }}>
      <textarea
        className="mono"
        placeholder={"One target per line, e.g.\napi.example.com\napp.example.com"}
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={5}
        style={{ ...inputStyle, width: "100%", resize: "vertical" }}
      />
      <div style={{ display: "flex", gap: 12, alignItems: "center", marginTop: 8, flexWrap: "wrap" }}>
        <select value={targetType} onChange={(e) => setTargetType(e.target.value)} style={inputStyle}>
          {TARGET_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--text-secondary)" }}>
          <input type="checkbox" checked={inScope} onChange={(e) => setInScope(e.target.checked)} />
          In scope
        </label>
      </div>
      {error && <p style={{ color: "var(--status-fail)", fontSize: 12, marginTop: 8 }}>{error}</p>}
      <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
        <button onClick={handleSubmit} disabled={submitting} style={primaryButtonStyle}>
          {submitting ? "Adding…" : "Add all"}
        </button>
        <button onClick={onCancel} style={secondaryButtonStyle}>
          Cancel
        </button>
      </div>
    </div>
  );
}

const inputStyle = {
  background: "var(--bg-surface-raised)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
  color: "var(--text-primary)",
  padding: "6px 10px",
  fontSize: 13,
  fontFamily: "var(--font-ui)",
};

const primaryButtonStyle = {
  background: "var(--accent)",
  color: "var(--on-accent)",
  border: "none",
  borderRadius: "var(--radius)",
  padding: "6px 14px",
  fontSize: 13,
  fontWeight: 500,
  cursor: "pointer",
};

const secondaryButtonStyle = {
  background: "transparent",
  color: "var(--text-secondary)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
  padding: "6px 14px",
  fontSize: 13,
  cursor: "pointer",
};

const linkButtonStyle = {
  background: "transparent",
  border: "none",
  color: "var(--accent)",
  fontSize: 12,
  cursor: "pointer",
  padding: 0,
};
