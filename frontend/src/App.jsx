import { useEffect, useRef, useState } from "react";
import { BrowserRouter, Routes, Route, useLocation, useNavigate } from "react-router-dom";
import { ProjectList } from "./pages/ProjectList";
import { Chronology } from "./pages/Chronology";
import { NewProject } from "./pages/NewProject";
import { ProjectDetail } from "./pages/ProjectDetail";
import { Dashboard } from "./pages/Dashboard";
import { Observability } from "./pages/Observability";
import { SignatureStats } from "./pages/SignatureStats";
import { ScheduledScans } from "./pages/ScheduledScans";
import { ExecutionQueue } from "./pages/ExecutionQueue";
import { TriageQueue } from "./pages/TriageQueue";
import { ReportBuilder } from "./pages/ReportBuilder";
import { CommandPalette } from "./components/CommandPalette";
import { Sidebar } from "./components/Sidebar";
import { ShortcutsModal } from "./components/ShortcutsModal";

function Shell() {
  const [collapsed, setCollapsed] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const gPending = useRef(false);
  const gTimer = useRef(null);
  const mainRef = useRef(null);
  // Per-history-entry scroll positions for the <main> pane. React
  // Router gives every navigation entry (including ones you land back
  // on via Alt+Left / the browser back button) a stable, unique
  // location.key - so remembering scrollTop per key and restoring it
  // on the way back is what makes "scroll down a project list, open a
  // project, hit back" land you where you left off instead of back at
  // the top. The browser's own scroll restoration only ever sees the
  // window, never this inner scrollable pane, so it can't do this on
  // its own.
  const scrollPositions = useRef(new Map());
  // The triage queue is a split-pane workspace, not a document - it
  // wants the full main area, not the ~960px reading-width column
  // every other page uses.
  const isFullBleed = location.pathname === "/triage" || location.pathname.startsWith("/report/");

  useEffect(() => {
    const mainEl = mainRef.current;
    if (!mainEl) return;

    function onScroll() {
      scrollPositions.current.set(location.key, mainEl.scrollTop);
    }

    mainEl.addEventListener("scroll", onScroll, { passive: true });
    mainEl.scrollTop = scrollPositions.current.get(location.key) || 0;

    return () => mainEl.removeEventListener("scroll", onScroll);
  }, [location.key]);

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
        const dest = { p: "/", d: "/dashboard", c: "/scheduled", s: "/signatures", n: "/new", t: "/triage", h: "/chronology", o: "/system", q: "/queue" }[
          e.key.toLowerCase()
        ];
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
    <div style={{ height: "100vh", display: "flex", overflow: "hidden" }}>
      <CommandPalette />
      {shortcutsOpen && <ShortcutsModal onClose={() => setShortcutsOpen(false)} />}
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed((c) => !c)} />

      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0, minHeight: 0 }}>
        <header
          style={{
            borderBottom: "1px solid var(--border)",
            padding: "12px 24px",
            display: "flex",
            alignItems: "center",
            justifyContent: "flex-end",
            flexShrink: 0,
          }}
        >
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn" onClick={() => setShortcutsOpen(true)} title="Keybind reference (?)">
              ? KEYS
            </button>
            <button
              className="btn"
              onClick={() => window.dispatchEvent(new Event("swas:open-palette"))}
              title="Command palette (⌘K)"
              style={{ minWidth: "auto" }}
            >
              ⌘K
            </button>
          </div>
        </header>

        <main ref={mainRef} style={{ flex: 1, minHeight: 0, overflowY: isFullBleed ? "hidden" : "auto", padding: "24px 24px" }}>
          <div style={isFullBleed ? { height: "100%" } : { maxWidth: 960, margin: "0 auto" }}>
            <Routes>
              <Route path="/" element={<ProjectList />} />
              <Route path="/chronology" element={<Chronology />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/system" element={<Observability />} />
              <Route path="/scheduled" element={<ScheduledScans />} />
              <Route path="/queue" element={<ExecutionQueue />} />
              <Route path="/triage" element={<TriageQueue />} />
              <Route path="/report/:findingId" element={<ReportBuilder />} />
              <Route path="/signatures" element={<SignatureStats />} />
              <Route path="/new" element={<NewProject />} />
              <Route path="/projects/:id" element={<ProjectDetail />} />
            </Routes>
          </div>
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
