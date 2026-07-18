import { BrowserRouter, Routes, Route, Link } from "react-router-dom";
import { ProjectList } from "./pages/ProjectList";
import { NewProject } from "./pages/NewProject";
import { ProjectDetail } from "./pages/ProjectDetail";
import { Dashboard } from "./pages/Dashboard";
import { SignatureStats } from "./pages/SignatureStats";
import { CommandPalette } from "./components/CommandPalette";

export function App() {
  return (
    <BrowserRouter>
      <CommandPalette />
      <div style={{ minHeight: "100%", display: "flex", flexDirection: "column" }}>
        <header
          style={{
            borderBottom: "1px solid var(--border)",
            padding: "14px 24px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 24 }}>
            <Link to="/" style={{ display: "flex", alignItems: "center", gap: 10, color: "var(--text-primary)" }}>
              <span
                aria-hidden="true"
                style={{
                  width: 8,
                  height: 8,
                  borderRadius: "50%",
                  background: "var(--signal)",
                  animation: "signal-pulse 2.2s ease-out infinite",
                }}
              />
              <span
                className="mono"
                style={{
                  fontFamily: "var(--font-display)",
                  fontWeight: 600,
                  fontSize: 16,
                  letterSpacing: "0.02em",
                }}
              >
                SWAS
              </span>
            </Link>
            <Link to="/dashboard" style={{ fontSize: 13, color: "var(--text-secondary)" }}>
              Dashboard
            </Link>
            <Link to="/signatures" style={{ fontSize: 13, color: "var(--text-secondary)" }}>
              Signature Stats
            </Link>
          </div>
          <span className="mono header-tagline" style={{ fontSize: 11, color: "var(--text-muted)", letterSpacing: "0.04em", display: "flex", alignItems: "center", gap: 12 }}>
            SECURITY WEB AUTOMATION SYSTEM
            <span style={{ border: "1px solid var(--border)", borderRadius: 4, padding: "2px 6px" }}>⌘K</span>
          </span>
        </header>

        <main style={{ flex: 1, padding: "32px 24px", maxWidth: 880, width: "100%", margin: "0 auto" }}>
          <Routes>
            <Route path="/" element={<ProjectList />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/signatures" element={<SignatureStats />} />
            <Route path="/new" element={<NewProject />} />
            <Route path="/projects/:id" element={<ProjectDetail />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
