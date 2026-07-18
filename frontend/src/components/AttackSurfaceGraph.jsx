import { useMemo } from "react";
import { useNavigate } from "react-router-dom";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEVERITY_COLOR = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};
const PLATFORM_LABEL = { bugcrowd: "Bugcrowd", hackerone: "HackerOne" };

/**
 * AttackSurfaceGraph.jsx - Batch 7's node-graph homepage view.
 *
 * Pure hand-rolled SVG, no graphing/physics library - this repo's
 * package.json only has react/react-dom/react-router-dom, and pulling
 * in d3-force (or similar) for one static radial layout felt like more
 * dependency surface than the visual is worth. Layout is a fixed
 * two-level radial: one hub node per platform (Bugcrowd/HackerOne),
 * project nodes evenly spaced on a ring around their platform's hub.
 * Nothing here is physics-simulated or draggable - it recomputes from
 * scratch on every render, which is fine at the scale this tool
 * actually operates at (dozens of projects, not thousands).
 *
 * Node size = finding count (sqrt-scaled so it doesn't blow up on a
 * project with hundreds of findings). Node color = highest severity
 * present among that project's findings, or the project's status color
 * if it has none yet - this is meant to answer "where's the risk"
 * at a glance, not just "what exists".
 */
export function AttackSurfaceGraph({ projects, findings }) {
  const navigate = useNavigate();

  const findingsByProject = useMemo(() => {
    const map = new Map();
    for (const f of findings) {
      if (!map.has(f.project_id)) map.set(f.project_id, { total: 0, bySeverity: {} });
      const entry = map.get(f.project_id);
      entry.total += 1;
      entry.bySeverity[f.severity] = (entry.bySeverity[f.severity] || 0) + 1;
    }
    return map;
  }, [findings]);

  const platforms = useMemo(() => {
    const groups = new Map();
    for (const p of projects) {
      if (!groups.has(p.platform)) groups.set(p.platform, []);
      groups.get(p.platform).push(p);
    }
    return [...groups.entries()];
  }, [projects]);

  const width = 760;
  const height = 520;
  const centerX = width / 2;
  const centerY = height / 2;
  const hubRadius = 130;
  const maxFindings = Math.max(1, ...projects.map((p) => findingsByProject.get(p.id)?.total || 0));

  function nodeRadiusFor(count) {
    // sqrt scale: a project with 4x the findings of another gets a
    // node only 2x the radius, not 4x - keeps one noisy project from
    // visually swallowing the whole graph.
    const minR = 10;
    const maxR = 26;
    return minR + (maxR - minR) * Math.sqrt(count / maxFindings);
  }

  function highestSeverityColor(projectId) {
    const entry = findingsByProject.get(projectId);
    if (!entry) return null;
    for (const sev of SEVERITY_ORDER) {
      if (entry.bySeverity[sev]) return SEVERITY_COLOR[sev];
    }
    return SEVERITY_COLOR.info;
  }

  // Two hubs side by side (or one centered, if only one platform is in
  // use) - each with its own ring of project nodes.
  const hubPositions = platforms.map((_, i) => {
    if (platforms.length === 1) return { x: centerX, y: centerY };
    const spread = 220;
    return { x: centerX + (i === 0 ? -spread : spread), y: centerY };
  });

  if (projects.length === 0) {
    return (
      <div style={{ padding: "48px 16px", textAlign: "center", color: "var(--text-muted)" }}>
        No projects yet - nothing to graph.
      </div>
    );
  }

  return (
    <div
      style={{
        border: "1px solid var(--border)", borderRadius: "var(--radius-lg)",
        background: "var(--bg-surface)", padding: 12, overflow: "auto",
      }}
    >
      <svg viewBox={`0 0 ${width} ${height}`} width="100%" style={{ minWidth: 600, display: "block" }}>
        {platforms.map(([platform, group], gi) => {
          const hub = hubPositions[gi];
          const n = group.length;
          return (
            <g key={platform}>
              {group.map((p, i) => {
                const angle = (2 * Math.PI * i) / n - Math.PI / 2;
                const x = hub.x + hubRadius * Math.cos(angle);
                const y = hub.y + hubRadius * Math.sin(angle) * 0.75; // slightly flattened ellipse, fits the panel better than a true circle
                const entry = findingsByProject.get(p.id);
                const r = nodeRadiusFor(entry?.total || 0);
                const color = highestSeverityColor(p.id) || `var(--proj-${p.status})`;
                return (
                  <g key={p.id}>
                    <line x1={hub.x} y1={hub.y} x2={x} y2={y} stroke="var(--border-strong)" strokeWidth={1} />
                    <circle
                      cx={x} cy={y} r={r}
                      fill={color} fillOpacity={0.25} stroke={color} strokeWidth={1.5}
                      style={{ cursor: "pointer" }}
                      onClick={() => navigate(`/projects/${p.id}`)}
                    >
                      <title>
                        {p.name} - {entry?.total || 0} finding{entry?.total === 1 ? "" : "s"}
                      </title>
                    </circle>
                    <text
                      x={x} y={y + r + 13} textAnchor="middle"
                      fontSize={10} fill="var(--text-secondary)"
                      style={{ cursor: "pointer", pointerEvents: "none" }}
                    >
                      {p.name.length > 16 ? `${p.name.slice(0, 15)}…` : p.name}
                    </text>
                  </g>
                );
              })}
              <circle cx={hub.x} cy={hub.y} r={22} fill="var(--bg-surface-raised)" stroke="var(--accent)" strokeWidth={2} />
              <text x={hub.x} y={hub.y + 4} textAnchor="middle" fontSize={11} fill="var(--accent)" className="mono">
                {PLATFORM_LABEL[platform] || platform}
              </text>
            </g>
          );
        })}
      </svg>
      <div style={{ display: "flex", gap: 16, padding: "4px 8px 0", flexWrap: "wrap" }}>
        {SEVERITY_ORDER.map((sev) => (
          <span key={sev} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11, color: "var(--text-muted)" }}>
            <span aria-hidden="true" style={{ width: 8, height: 8, borderRadius: "50%", background: SEVERITY_COLOR[sev] }} />
            {sev}
          </span>
        ))}
        <span style={{ fontSize: 11, color: "var(--text-muted)" }}>· node size = finding count · click a node to open the project</span>
      </div>
    </div>
  );
}
