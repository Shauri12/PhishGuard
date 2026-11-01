import { useState, useEffect } from 'react';
import { getHistory } from '../api/client';
import { RiskBadge, Spinner, EmptyState } from '../components/Shared';

export default function DetectionHistory() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch]   = useState('');
  const [filter, setFilter]   = useState('all');
  const [page, setPage]       = useState(1);
  const PER_PAGE = 20;

  useEffect(() => {
    getHistory(500)
      .then(r => setHistory(r.data?.items || r.data?.history || []))
      .catch(() => setHistory([]))
      .finally(() => setLoading(false));
  }, []);

  function exportCSV() {
    const rows = [['URL', 'Risk Level', 'Probability', 'Timestamp']];
    history.forEach(h => rows.push([
      `"${(h.url || '').replace(/"/g, '""')}"`,
      h.risk_level,
      h.probability?.toFixed(4),
      h.timestamp || '',
    ]));
    const blob = new Blob([rows.map(r => r.join(',')).join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `phishguard_history_${Date.now()}.csv`;
    a.click();
  }

  if (loading) return <Spinner />;

  const filtered = history
    .filter(h => filter === 'all' || (h.risk_level || '').toLowerCase().includes(filter))
    .filter(h => !search || (h.url || '').toLowerCase().includes(search.toLowerCase()));

  const totalPages = Math.ceil(filtered.length / PER_PAGE);
  const slice = filtered.slice().reverse().slice((page - 1) * PER_PAGE, page * PER_PAGE);

  const counts = {
    all: history.length,
    safe: history.filter(h => (h.risk_level||'') === 'safe').length,
    warning: history.filter(h => ['warning','suspicious'].includes(h.risk_level||'')).length,
    phishing: history.filter(h => (h.risk_level||'') === 'phishing').length,
  };

  return (
    <div className="page-body">
      <div className="page-header">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div className="page-title">📋 Detection History</div>
            <div className="page-subtitle">{history.length} total URL scans recorded</div>
          </div>
          <button className="btn btn-outline" onClick={exportCSV}>📥 Export CSV</button>
        </div>
      </div>

      {/* Filter row */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          <input
            type="text"
            placeholder="Search URLs…"
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1); }}
            style={{ flex: 1, minWidth: 200 }}
          />
          {['all', 'safe', 'warning', 'phishing'].map(f => (
            <button key={f} className={`btn btn-sm ${filter === f ? 'btn-primary' : 'btn-outline'}`}
              onClick={() => { setFilter(f); setPage(1); }}
            >
              {f.toUpperCase()} ({counts[f] || 0})
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      {slice.length > 0 ? (
        <>
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>URL</th>
                  <th>Risk Level</th>
                  <th>Score</th>
                  <th>Timestamp</th>
                  <th>Label</th>
                </tr>
              </thead>
              <tbody>
                {slice.map((h, i) => (
                  <tr key={i}>
                    <td style={{ color: 'var(--text3)', fontSize: 11, width: 40 }}>
                      {(page - 1) * PER_PAGE + i + 1}
                    </td>
                    <td className="url-cell" title={h.url}>{h.url}</td>
                    <td><RiskBadge level={h.risk_level} /></td>
                    <td style={{ fontVariantNumeric: 'tabular-nums', fontFamily: 'monospace', fontSize: 12 }}>
                      {h.probability != null ? (h.probability * 100).toFixed(2) + '%' : '—'}
                    </td>
                    <td style={{ color: 'var(--text3)', fontSize: 12, whiteSpace: 'nowrap' }}>
                      {h.timestamp ? new Date(h.timestamp).toLocaleString() : '—'}
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text3)' }}>
                      {h.verdict || (h.prediction === 1 ? 'PHISHING' : 'LEGITIMATE')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 16 }}>
              <button className="btn btn-outline btn-sm" disabled={page === 1} onClick={() => setPage(p => p - 1)}>← Prev</button>
              <span style={{ padding: '5px 10px', color: 'var(--text3)', fontSize: 12 }}>
                Page {page} / {totalPages}
              </span>
              <button className="btn btn-outline btn-sm" disabled={page === totalPages} onClick={() => setPage(p => p + 1)}>Next →</button>
            </div>
          )}
        </>
      ) : (
        <EmptyState icon="📭" title="No detections found" sub="Try adjusting the filter or scan some URLs first." />
      )}
    </div>
  );
}

