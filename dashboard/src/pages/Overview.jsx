import { useEffect, useState } from 'react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts';
import { checkHealth, getStats, getHistory } from '../api/client';
import { MetricCard, RiskBadge, Spinner } from '../components/Shared';

const COLORS = { safe: '#10B981', warning: '#F59E0B', phishing: '#EF4444' };

function normalizeRisk(level) {
  const l = (level || 'safe').toLowerCase();
  if (['phishing', 'blocked', 'dangerous'].includes(l)) return 'phishing';
  if (['warning', 'suspicious', 'warn'].includes(l)) return 'warning';
  return 'safe';
}

function buildTrend(history) {
  const buckets = {};
  history.forEach(h => {
    const day = new Date(h.timestamp || h.ts || Date.now()).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    if (!buckets[day]) buckets[day] = { day, safe: 0, warning: 0, phishing: 0 };
    const lvl = normalizeRisk(h.risk_level);
    if (buckets[day][lvl] !== undefined) buckets[day][lvl]++;
  });
  return Object.values(buckets).slice(-14);
}

function buildPie(history) {
  const counts = { safe: 0, warning: 0, phishing: 0 };
  history.forEach(h => {
    const lvl = normalizeRisk(h.risk_level);
    if (counts[lvl] !== undefined) counts[lvl]++;
  });
  return Object.entries(counts).map(([name, value]) => ({ name, value }));
}

export default function Overview() {
  const [health, setHealth]   = useState(null);
  const [stats, setStats]     = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      checkHealth(),
      getStats(),
      getHistory(500),
    ]).then(([h, s, hist]) => {
      if (h.status === 'fulfilled') setHealth(h.value.data);
      if (s.status === 'fulfilled') setStats(s.value.data);
      if (hist.status === 'fulfilled') {
        const rows = hist.value.data?.items || hist.value.data?.history || [];
        setHistory(rows);
      }
      setLoading(false);
    });
  }, []);

  if (loading) return <Spinner />;

  const total    = history.length;
  const safe     = history.filter(h => normalizeRisk(h.risk_level) === 'safe').length;
  const warned   = history.filter(h => normalizeRisk(h.risk_level) === 'warning').length;
  const blocked  = history.filter(h => normalizeRisk(h.risk_level) === 'phishing').length;
  const avgScore = total ? (history.reduce((s, h) => s + (h.probability || 0), 0) / total * 100).toFixed(1) : 0;

  const trend  = buildTrend(history);
  const pieData = buildPie(history);
  const recent = history.slice().reverse().slice(0, 8);

  return (
    <div className="page-body">
      {/* Header */}
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, justifyContent: 'space-between' }}>
          <div>
            <div className="page-title">🛡️ Threat Overview</div>
            <div className="page-subtitle">Real-time monitoring dashboard · All detection activity</div>
          </div>
          {health && (
            <div className="live-badge">
              <span className="live-dot" />
              {health.status === 'healthy' ? 'Backend Online' : 'Backend Offline'}
            </div>
          )}
        </div>
      </div>

      {/* Metric cards */}
      <div className="metrics-grid">
        <MetricCard icon="🔎" label="Total Scans"    value={total}    sub="All-time URL scans" />
        <MetricCard icon="✅" label="Safe Sites"     value={safe}     sub={`${total ? ((safe/total)*100).toFixed(0) : 0}% of total`} color="var(--safe)"   />
        <MetricCard icon="⚠️" label="Warnings"       value={warned}   sub={`${total ? ((warned/total)*100).toFixed(0) : 0}% of total`} color="var(--warn)" />
        <MetricCard icon="🛑" label="Threats Blocked" value={blocked}  sub={`${total ? ((blocked/total)*100).toFixed(0) : 0}% of total`} color="var(--danger)" />
      </div>

      {/* Trend + Pie */}
      <div className="two-col" style={{ marginBottom: 20 }}>
        <div className="chart-card">
          <div className="chart-title">📈 Detection Trend (Last 14 Days)</div>
          {trend.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={trend} margin={{ top: 4, right: 10, bottom: 0, left: -20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="day" tick={{ fill: '#64748B', fontSize: 11 }} />
                <YAxis tick={{ fill: '#64748B', fontSize: 11 }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#1E2732', border: '1px solid rgba(255,255,255,.1)', borderRadius: 8, fontSize: 12 }} />
                <Line type="monotone" dataKey="safe"     stroke="#10B981" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="warning"  stroke="#F59E0B" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="phishing" stroke="#EF4444" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ textAlign: 'center', padding: 40, color: 'var(--text3)' }}>No scan data yet</div>
          )}
        </div>

        <div className="chart-card">
          <div className="chart-title">🥧 Risk Distribution</div>
          {total > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={({ name, percent }) => `${name} ${(percent*100).toFixed(0)}%`} labelLine={false} fontSize={11}>
                  {pieData.map(entry => (
                    <Cell key={entry.name} fill={COLORS[entry.name] || '#6366F1'} />
                  ))}
                </Pie>
                <Legend wrapperStyle={{ fontSize: 12, color: 'var(--text2)' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ textAlign: 'center', padding: 40, color: 'var(--text3)' }}>No data yet</div>
          )}
        </div>
      </div>

      {/* Model health */}
      {health && (
        <div className="card" style={{ marginBottom: 20 }}>
          <div className="card-title">⚙️ Model Status</div>
          <div style={{ display: 'flex', gap: 32, flexWrap: 'wrap', fontSize: 13 }}>
            <div><span style={{ color: 'var(--text3)' }}>Status:</span> <span style={{ color: 'var(--safe)', fontWeight: 700 }}>{health.status?.toUpperCase()}</span></div>
            <div><span style={{ color: 'var(--text3)' }}>Model Loaded:</span> <span style={{ color: 'var(--text)' }}>{health.model_loaded ? '✅ Yes' : '❌ No'}</span></div>
            <div><span style={{ color: 'var(--text3)' }}>Features:</span> <span style={{ color: 'var(--accent)' }}>{health.features_count}</span></div>
            <div><span style={{ color: 'var(--text3)' }}>Avg Phishing Score:</span> <span style={{ color: 'var(--warn)' }}>{avgScore}%</span></div>
            <div><span style={{ color: 'var(--text3)' }}>Version:</span> <span style={{ color: 'var(--text)' }}>{health.version || '1.0.0'}</span></div>
          </div>
        </div>
      )}

      {/* Recent scans */}
      <div className="chart-card">
        <div className="chart-title">🕐 Recent Detections</div>
        {recent.length > 0 ? (
          <div className="table-wrapper" style={{ border: 'none' }}>
            <table>
              <thead>
                <tr>
                  <th>URL</th><th>Risk Level</th><th>Score</th><th>Time</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((h, i) => (
                  <tr key={i}>
                    <td className="url-cell" title={h.url}>{h.url}</td>
                    <td><RiskBadge level={h.risk_level} /></td>
                    <td style={{ fontVariantNumeric: 'tabular-nums' }}>
                      {h.probability != null ? (h.probability * 100).toFixed(1) + '%' : '—'}
                    </td>
                    <td style={{ color: 'var(--text3)', fontSize: 12 }}>
                      {h.timestamp ? new Date(h.timestamp).toLocaleTimeString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ textAlign: 'center', padding: 30, color: 'var(--text3)' }}>
            No detections yet — run a scan or browse with the Chrome Extension.
          </div>
        )}
      </div>
    </div>
  );
}

