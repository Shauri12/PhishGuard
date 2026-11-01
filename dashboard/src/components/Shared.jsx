export function RiskBadge({ level }) {
  const map = {
    safe:     { cls: 'safe',     label: 'SAFE'     },
    warning:  { cls: 'warning',  label: 'WARN'     },
    suspicious:{ cls:'warning',  label: 'SUSPICIOUS'},
    phishing: { cls: 'phishing', label: 'PHISHING' },
    error:    { cls: 'error',    label: 'ERROR'    },
  };
  const { cls, label } = map[level?.toLowerCase()] || { cls: 'error', label: level || 'UNKNOWN' };
  return <span className={`badge ${cls}`}>{label}</span>;
}

export function MetricCard({ icon, label, value, sub, color }) {
  return (
    <div className="metric-card">
      <div className="metric-icon">{icon}</div>
      <div className="metric-label">{label}</div>
      <div className="metric-value" style={color ? { color } : {}}>{value ?? '—'}</div>
      {sub && <div className="metric-sub">{sub}</div>}
    </div>
  );
}

export function Spinner() {
  return <div className="loading-center"><div className="spinner" /></div>;
}

export function EmptyState({ icon = '📭', title, sub }) {
  return (
    <div className="empty-state">
      <div style={{ fontSize: 36, marginBottom: 12 }}>{icon}</div>
      <h3>{title}</h3>
      {sub && <p style={{ fontSize: 12, marginTop: 4 }}>{sub}</p>}
    </div>
  );
}

export function SectionHeader({ title, children }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
      <div className="chart-title">{title}</div>
      {children}
    </div>
  );
}

