import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";

const NAV = [
  { to: "/", label: "Projects", keys: "G P", icon: "▣" },
  { to: "/dashboard", label: "Dashboard", keys: "G D", icon: "◈" },
  { to: "/signatures", label: "Signatures", keys: "G S", icon: "◉" },
  { to: "/new", label: "New Project", keys: "G N", icon: "+" },
];

export function Sidebar({ collapsed, onToggle }) {
  const location = useLocation();
  const [clock, setClock] = useState(() => new Date());

  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const time = clock.toISOString().slice(11, 19) + "Z";

  return (
    <aside
      style={{
        width: collapsed ? "var(--sidebar-w-collapsed)" : "var(--sidebar-w)",
        flexShrink: 0,
        borderRight: "1px solid var(--border)",
        background: "var(--bg-surface)",
        display: "flex",
        flexDirection: "column",
        transition: "width 0.15s ease",
        overflow: "hidden",
      }}
    >
      <div
        style={{
          padding: collapsed ? "16px 0" : "16px 18px",
          display: "flex",
          alignItems: "center",
          justifyContent: collapsed ? "center" : "space-between",
          borderBottom: "1px solid var(--border)",
        }}
      >
        <Link to="/" style={{ display: "flex", alignItems: "center", gap: 9, color: "var(--text-primary)" }}>
          <span
            aria-hidden="true"
            style={{
              width: 7,
              height: 7,
              borderRadius: "50%",
              background: "var(--signal)",
              animation: "signal-pulse 2.2s ease-out infinite",
              flexShrink: 0,
            }}
          />
          {!collapsed && (
            <span style={{ fontFamily: "var(--font-display)", fontWeight: 600, fontSize: 17, letterSpacing: "0.02em" }}>
              SWAS
            </span>
          )}
        </Link>
      </div>

      <nav style={{ padding: "12px 8px", display: "flex", flexDirection: "column", gap: 2, flex: 1 }}>
        {NAV.map((item) => {
          const active = item.to === "/" ? location.pathname === "/" : location.pathname.startsWith(item.to);
          return (
            <Link
              key={item.to}
              to={item.to}
              title={collapsed ? `${item.label} (${item.keys})` : undefined}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                justifyContent: collapsed ? "center" : "flex-start",
                padding: collapsed ? "9px 0" : "9px 10px",
                borderRadius: "var(--radius)",
                color: active ? "var(--accent)" : "var(--text-secondary)",
                background: active ? "var(--accent-dim)" : "transparent",
                fontSize: 13,
                fontWeight: 500,
                textDecoration: "none",
              }}
            >
              <span aria-hidden="true" className="mono" style={{ width: 14, textAlign: "center", fontSize: 13 }}>
                {item.icon}
              </span>
              {!collapsed && <span style={{ flex: 1 }}>{item.label}</span>}
              {!collapsed && (
                <span className="kbd" style={{ opacity: 0.7 }}>
                  {item.keys}
                </span>
              )}
            </Link>
          );
        })}
      </nav>

      <div style={{ padding: collapsed ? "10px 0" : "10px 12px", borderTop: "1px solid var(--border)" }}>
        {!collapsed && (
          <div className="mono" style={{ fontSize: 10, color: "var(--text-muted)", letterSpacing: "0.06em", marginBottom: 8 }}>
            {time}
          </div>
        )}
        <button
          className="btn"
          onClick={onToggle}
          title={collapsed ? "Expand sidebar ([)" : "Collapse sidebar ([)"}
          style={{ width: "100%", justifyContent: "center", padding: "6px 0" }}
        >
          {collapsed ? "»" : "« COLLAPSE"}
        </button>
      </div>
    </aside>
  );
}
