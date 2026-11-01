import { useEffect, useState } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  AreaChart, Area, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
} from 'recharts';
import { getHistory } from '../api/client';
import { Spinner } from '../components/Shared';

function topDomains(history, n = 10) {
  const counts = {};
  history.filter(h => (h.risk_level||'') === 'phishing').forEach(h => {
    try {
      const d = new URL(h.url).hostname;
      counts[d] = (counts[d] || 0) + 1;
    } catch {}
  });
  return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, n).map(([domain, count]) => ({ domain: domain.slice(0, 28), count }));
}

function topTLDs(history, n = 8) {
  const counts = {};
  history.forEach(h => {
    try {
      const parts = new URL(h.url).hostname.split('.');
      const tld = '.' + parts[parts.length - 1];
      counts[tld] = (counts[tld] || 0) + 1;
    } catch {}
  });
  return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, n).map(([tld, count]) => ({ tld, count }));
}

function hourlyHeatmap(history) {
  const buckets = Array.from({ length: 24 }, (_, h) => ({ hour: h + ':00', scans: 0, phishing: 0 }));
  history.forEach(h => {
    if (!h.timestamp) return;
    const hr = new Date(h.timestamp).getHours();
    buckets[hr].scans++;
    if ((h.risk_level||'') === 'phishing') buckets[hr].phishing++;
  });
  return buckets;
}

export default function Analytics() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getHistory(1000)
      .then(r => setHistory(r.data?.items || r.data?.history || []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <Spinner />;

  const phishing = history.filter(h => (h.risk_level||'') === 'phishing');
  const safe     = history.filter(h => (h.risk_level||'') === 'safe');
  const warned   = history.filter(h => ['warning','suspicious'].includes(h.risk_level||''));

  const total = history.length || 1;
  const detectionRate = ((phishing.length / total) * 100).toFixed(1);
  const safeRate      = ((safe.length / total) * 100).toFixed(1);
  const avgProb       = history.length ? (history.reduce((s, h) => s + (h.probability || 0), 0) / history.length * 100).toFixed(1) : 0;

  const domains  = topDomains(history);
  const tlds     = topTLDs(history);
  const hourly   = hourlyHeatmap(history);

  const radarData = [
    { metric: 'Accuracy',       value: 99.9 },
    { metric: 'Recall',         value: 99.7 },
    { metric: 'Precision',      value: 98.8 },
    { metric: 'F1 Score',       value: 99.2 },
    { metric: 'AUC-ROC',        value: 99.9 },
    { metric: 'FP Rate (inv)',  value: 99.4 },
  ];

  return (
    <div className="page-body">
      <div className="page-header">
        <div className="page-title">📈 Analytics & SHAP Insights</div>
        <div className="page-subtitle">Model performance, detection patterns, and threat intelligence</div>
      </div>

      {/* KPI Row */}
      <div className="metrics-grid" style={{ marginBottom: 20 }}>
        <div className="metric-card">
          <div className="metric-icon">🎯</div>
          <div className="metric-label">Threat Detection Rate</div>
          <div className="metric-value" style={{ color: 'var(--danger)' }}>{detectionRate}%</div>
          <div className="metric-sub">Of all scanned URLs</div>
        </div>
        <div className="metric-card">
          <div className="metric-icon">✅</div>
          <div className="metric-label">Safe Pass Rate</div>
          <div className="metric-value" style={{ color: 'var(--safe)' }}>{safeRate}%</div>
          <div className="metric-sub">Zero-friction for legit sites</div>
        </div>
        <div className="metric-card">
          <div className="metric-icon">📊</div>
          <div className="metric-label">Avg Phishing Score</div>
          <div className="metric-value" style={{ color: 'var(--warn)' }}>{avgProb}%</div>
          <div className="metric-sub">Mean probability across scans</div>
        </div>
        <div className="metric-card">
          <div className="metric-icon">🧠</div>
          <div className="metric-label">Model Accuracy</div>
          <div className="metric-value" style={{ color: 'var(--accent)' }}>99.9%</div>
          <div className="metric-sub">Trained on PhiUSIIL dataset</div>
        </div>
      </div>

      {/* Radar chart + Top Domains */}
      <div className="two-col" style={{ marginBottom: 20 }}>
        <div className="chart-card">
          <div className="chart-title">🧠 Model Performance Metrics</div>
          <ResponsiveContainer width="100%" height={240}>
            <RadarChart data={radarData} cx="50%" cy="50%" outerRadius={80}>
              <PolarGrid stroke="rgba(255,255,255,0.08)" />
              <PolarAngleAxis dataKey="metric" tick={{ fill: '#64748B', fontSize: 11 }} />
              <PolarRadiusAxis angle={90} domain={[90, 100]} tick={{ fill: '#64748B', fontSize: 10 }} />
              <Radar name="Score" dataKey="value" stroke="#6366F1" fill="#6366F1" fillOpacity={0.25} />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <div className="chart-title">🌐 Top Phishing Domains Detected</div>
          {domains.length > 0 ? (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={domains} layout="vertical" margin={{ top: 0, right: 10, bottom: 0, left: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                <XAxis type="number" tick={{ fill: '#64748B', fontSize: 11 }} allowDecimals={false} />
                <YAxis type="category" dataKey="domain" tick={{ fill: '#94A3B8', fontSize: 10 }} width={140} />
                <Tooltip contentStyle={{ background: '#1E2732', border: '1px solid rgba(255,255,255,.1)', borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="count" fill="#EF4444" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ textAlign: 'center', padding: 40, color: 'var(--text3)' }}>No phishing domains recorded yet</div>
          )}
        </div>
      </div>

      {/* TLD chart + Hourly */}
      <div className="two-col" style={{ marginBottom: 20 }}>
        <div className="chart-card">
          <div className="chart-title">🏷️ Top TLDs Scanned</div>
          {tlds.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={tlds} margin={{ top: 4, right: 10, bottom: 0, left: -20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="tld" tick={{ fill: '#64748B', fontSize: 11 }} />
                <YAxis tick={{ fill: '#64748B', fontSize: 11 }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#1E2732', border: '1px solid rgba(255,255,255,.1)', borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="count" fill="#6366F1" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ textAlign: 'center', padding: 40, color: 'var(--text3)' }}>No TLD data yet</div>
          )}
        </div>

        <div className="chart-card">
          <div className="chart-title">🕐 Scan Activity by Hour</div>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={hourly} margin={{ top: 4, right: 10, bottom: 0, left: -20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="hour" tick={{ fill: '#64748B', fontSize: 10 }} interval={3} />
              <YAxis tick={{ fill: '#64748B', fontSize: 11 }} allowDecimals={false} />
              <Tooltip contentStyle={{ background: '#1E2732', border: '1px solid rgba(255,255,255,.1)', borderRadius: 8, fontSize: 12 }} />
              <Area type="monotone" dataKey="scans"    stroke="#6366F1" fill="rgba(99,102,241,0.15)" strokeWidth={2} />
              <Area type="monotone" dataKey="phishing" stroke="#EF4444" fill="rgba(239,68,68,0.10)"  strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Phishing Summary */}
      <div className="card">
        <div className="card-title">📊 Detection Summary</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 20, fontSize: 13 }}>
          {[
            { label: 'Confirmed Phishing', val: phishing.length, c: 'var(--danger)' },
            { label: 'Suspicious / Warned', val: warned.length,  c: 'var(--warn)'   },
            { label: 'Safe / Legitimate',   val: safe.length,    c: 'var(--safe)'   },
          ].map(x => (
            <div key={x.label} style={{ textAlign: 'center', padding: '12px 0' }}>
              <div style={{ fontSize: 32, fontWeight: 800, color: x.c }}>{x.val}</div>
              <div style={{ color: 'var(--text3)', fontSize: 12, marginTop: 4 }}>{x.label}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

