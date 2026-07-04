/**
 * Donut.jsx - a small, dependency-free ring chart.
 *
 * Deliberately hand-rolled SVG rather than a charting library: the data
 * here is always a handful of severity/status buckets, never a real
 * time series, so a library's axis/tooltip/animation machinery would be
 * overhead for something this simple to draw by hand with stroke-dasharray.
 */

const SIZE = 88;
const STROKE = 12;
const RADIUS = (SIZE - STROKE) / 2;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

/**
 * segments: [{ key, label, value, color }, ...] - order determines
 * draw order (and therefore legend order). Zero-value segments are
 * skipped from the ring but can still appear in the legend by the
 * caller if desired.
 */
export function Donut({ segments, centerLabel }) {
  const total = segments.reduce((sum, s) => sum + s.value, 0);

  let offset = 0;
  const arcs = segments
    .filter((s) => s.value > 0)
    .map((s) => {
      const fraction = total > 0 ? s.value / total : 0;
      const length = fraction * CIRCUMFERENCE;
      const arc = (
        <circle
          key={s.key}
          cx={SIZE / 2}
          cy={SIZE / 2}
          r={RADIUS}
          fill="none"
          stroke={s.color}
          strokeWidth={STROKE}
          strokeDasharray={`${length} ${CIRCUMFERENCE - length}`}
          strokeDashoffset={-offset}
          transform={`rotate(-90 ${SIZE / 2} ${SIZE / 2})`}
        />
      );
      offset += length;
      return arc;
    });

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
      <svg width={SIZE} height={SIZE} viewBox={`0 0 ${SIZE} ${SIZE}`} role="img" aria-label="Severity distribution">
        <circle cx={SIZE / 2} cy={SIZE / 2} r={RADIUS} fill="none" stroke="var(--border)" strokeWidth={STROKE} />
        {arcs}
        <text
          x={SIZE / 2}
          y={SIZE / 2}
          textAnchor="middle"
          dominantBaseline="central"
          className="mono"
          fill="var(--text-primary)"
          fontSize={total > 999 ? 16 : 20}
          fontWeight={600}
        >
          {total}
        </text>
      </svg>

      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        {segments.map((s) => (
          <div key={s.key} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12 }}>
            <span
              aria-hidden="true"
              style={{ width: 8, height: 8, borderRadius: 2, background: s.color, flexShrink: 0 }}
            />
            <span style={{ color: "var(--text-secondary)", minWidth: 56 }}>{s.label}</span>
            <span className="mono" style={{ color: "var(--text-primary)", fontWeight: 500 }}>
              {s.value}
            </span>
          </div>
        ))}
      </div>
      {centerLabel && (
        <span style={{ fontSize: 11, color: "var(--text-muted)" }}>{centerLabel}</span>
      )}
    </div>
  );
}
