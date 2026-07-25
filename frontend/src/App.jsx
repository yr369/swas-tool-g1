import { useEffect, useRef, useState } from "react";
import { BrowserRouter, Routes, Route, useNavigate } from "react-router-dom";
import { ProjectList } from "./pages/ProjectList";
import { NewProject } from "./pages/NewProject";
import { ProjectDetail } from "./pages/ProjectDetail";
import { Dashboard } from "./pages/Dashboard";
import { SignatureStats } from "./pages/SignatureStats";
import { CommandPalette } from "./components/CommandPalette";
import { Sidebar } from "./components/Sidebar";
import { ShortcutsModal } from "./components/ShortcutsModal";

function Shell() {
  const [collapsed, setCollapsed] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const navigate = useNavigate();
  const gPending = useRef(false);
  const gTimer = useRef(null);

  useEffect(() => {
    function isTypingTarget(el) {
      return el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.isContentEditable);
    }

    function onKeyDown(e) {
      if (isTypingTarget(e.target)) return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;

      if (gPending.current) {
        gPending.current = false;
        clearTimeout(gTimer.current);
        const dest = { p: "/", d: "/dashboard", s: "/signatures", n: "/new" }[e.key.toLowerCase()];
        if (dest) {
          e.preventDefault();
          navigate(dest);
        }
        return;
      }

      if (e.key.toLowerCase() === "g") {
        gPending.current = true;
        gTimer.current = setTimeout(() => (gPending.current = false), 900);
        return;
      }
      if (e.key === "?") {
        setShortcutsOpen(true);
        return;
      }
      if (e.key === "[") {
        setCollapsed((c) => !c);
        return;
      }
      if (e.key === "Escape") {
        setShortcutsOpen(false);
      }
    }

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [navigate]);

  return (
    <div style={{ minHeight: "100%", display: "flex" }}>
      <CommandPalette />
      {shortcutsOpen && <ShortcutsModal onClose={() => setShortcutsOpen(false)} />}
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed((c) => !c)} />

      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
        <header
          style={{
            borderBottom: "1px solid var(--border)",
            padding: "12px 24px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <span className="eyebrow header-tagline">SECURITY WEB AUTOMATION SYSTEM</span>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn" onClick={() => setShortcutsOpen(true)} title="Keybind reference (?)">
              ? KEYS
            </button>
            <span className="kbd" style={{ minWidth: "auto", padding: "2px 8px" }}>
              ⌘K
            </span>
          </div>
        </header>

        <main style={{ flex: 1, padding: "32px 28px", maxWidth: 960, width: "100%", margin: "0 auto" }}>
          <Routes>
            <Route path="/" element={<ProjectList />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/signatures" element={<SignatureStats />} />
            <Route path="/new" element={<NewProject />} />
            <Route path="/projects/:id" element={<ProjectDetail />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <Shell />
    </BrowserRouter>
  );
}
