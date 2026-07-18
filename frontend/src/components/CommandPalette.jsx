import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";

/**
 * CommandPalette.jsx - global Cmd+K / Ctrl+K launcher (Batch 7).
 *
 * Mounted once in App.jsx, outside the <Routes> tree, so it works from
 * any page. Lazily loads the project list the first time it's opened
 * (not on every keystroke, not on app load) - this is a "jump to
 * anything fast" tool, not something that needs to be instantly ready
 * before the operator has even pressed the shortcut once.
 *
 * Static actions (New project, Dashboard, Signature stats) are always
 * present; projects are matched by a simple case-insensitive substring
 * search on name - deliberately not a fuzzy-match library, since a
 * small personal project list doesn't need one and it's one less
 * dependency to add to package.json.
 */
export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [projects, setProjects] = useState(null);
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef(null);
  const navigate = useNavigate();

  // Global shortcut: Cmd+K on Mac, Ctrl+K everywhere else. Escape closes
  // it from anywhere, even while an input elsewhere on the page has focus.
  useEffect(() => {
    function onKeyDown(e) {
      const isModK = (e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k";
      if (isModK) {
        e.preventDefault();
        setOpen((prev) => !prev);
      } else if (e.key === "Escape" && open) {
        setOpen(false);
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open]);

  useEffect(() => {
    if (open) {
      setQuery("");
      setActiveIndex(0);
      // Focus after the modal actually mounts, not before.
      setTimeout(() => inputRef.current?.focus(), 0);
      if (projects === null) {
        api.listProjects().then(setProjects).catch(() => setProjects([]));
      }
    }
  }, [open]); // eslint-disable-line react-hooks/exhaustive-deps -- projects intentionally excluded, loaded once and cached

  const staticActions = useMemo(
    () => [
      { id: "action:new-project", label: "New project", hint: "Create", go: () => navigate("/new") },
      { id: "action:dashboard", label: "Dashboard", hint: "Go to", go: () => navigate("/dashboard") },
      { id: "action:signatures", label: "Signature stats", hint: "Go to", go: () => navigate("/signatures") },
      { id: "action:projects", label: "All projects", hint: "Go to", go: () => navigate("/") },
    ],
    [navigate]
  );

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    const matchedProjects = (projects || [])
      .filter((p) => !q || p.name.toLowerCase().includes(q))
      .slice(0, 8)
      .map((p) => ({
        id: `project:${p.id}`,
        label: p.name,
        hint: p.platform === "bugcrowd" ? "Bugcrowd" : "HackerOne",
        go: () => navigate(`/projects/${p.id}`),
      }));
    const matchedActions = staticActions.filter((a) => !q || a.label.toLowerCase().includes(q));
    return [...matchedActions, ...matchedProjects];
  }, [query, projects, staticActions, navigate]);

  useEffect(() => {
    setActiveIndex(0);
  }, [query]);

  function choose(item) {
    if (!item) return;
    item.go();
    setOpen(false);
  }

  function onInputKeyDown(e) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActiveIndex((i) => Math.min(i + 1, results.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActiveIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      choose(results[activeIndex]);
    }
  }

  if (!open) return null;

  return (
    <div
      style={{
        position: "fixed", inset: 0, background: "rgba(0,0,0,0.55)",
        display: "flex", alignItems: "flex-start", justifyContent: "center",
        paddingTop: "12vh", zIndex: 200,
      }}
      onClick={() => setOpen(false)}
    >
      <div
        style={{
          background: "var(--bg-surface-raised)", border: "1px solid var(--border-strong)",
          borderRadius: "var(--radius-lg)", width: 560, maxWidth: "90vw",
          boxShadow: "0 16px 48px rgba(0,0,0,0.4)", overflow: "hidden",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <input
          ref={inputRef}
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={onInputKeyDown}
          placeholder="Jump to a project or action…"
          style={{
            width: "100%", boxSizing: "border-box", background: "transparent",
            border: "none", borderBottom: "1px solid var(--border)",
            padding: "16px 18px", fontSize: 15, color: "var(--text-primary)", outline: "none",
          }}
        />
        <div style={{ maxHeight: "50vh", overflowY: "auto", padding: "6px 0" }}>
          {results.length === 0 && (
            <div style={{ padding: "16px 18px", fontSize: 13, color: "var(--text-muted)" }}>No matches.</div>
          )}
          {results.map((item, i) => (
            <div
              key={item.id}
              onMouseEnter={() => setActiveIndex(i)}
              onClick={() => choose(item)}
              style={{
                display: "flex", justifyContent: "space-between", alignItems: "center",
                padding: "10px 18px", cursor: "pointer", fontSize: 13,
                background: i === activeIndex ? "var(--accent-dim)" : "transparent",
                color: i === activeIndex ? "var(--accent)" : "var(--text-primary)",
              }}
            >
              <span>{item.label}</span>
              <span className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>{item.hint}</span>
            </div>
          ))}
        </div>
        <div
          style={{
            display: "flex", gap: 14, padding: "8px 18px", borderTop: "1px solid var(--border)",
            fontSize: 11, color: "var(--text-muted)",
          }}
        >
          <span>↑↓ navigate</span>
          <span>↵ select</span>
          <span>esc close</span>
        </div>
      </div>
    </div>
  );
}
