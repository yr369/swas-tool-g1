import { BrowserRouter, Routes, Route, Link } from "react-router-dom";
import { ProjectList } from "./pages/ProjectList";
import { NewProject } from "./pages/NewProject";
import { ProjectDetail } from "./pages/ProjectDetail";

export function App() {
  return (
    <BrowserRouter>
      <div style={{ minHeight: "100%", display: "flex", flexDirection: "column" }}>
        <header
          style={{
            borderBottom: "1px solid var(--border)",
            padding: "14px 24px",
            display: "flex",
            alignItems: "center",
          }}
        >
          <Link to="/" style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--text-primary)" }}>
            <span style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--accent)" }} aria-hidden="true" />
            <span className="mono" style={{ fontWeight: 600, fontSize: 14, letterSpacing: "0.02em" }}>
              SWAS
            </span>
          </Link>
        </header>

        <main style={{ flex: 1, padding: "32px 24px", maxWidth: 880, width: "100%", margin: "0 auto" }}>
          <Routes>
            <Route path="/" element={<ProjectList />} />
            <Route path="/new" element={<NewProject />} />
            <Route path="/projects/:id" element={<ProjectDetail />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
