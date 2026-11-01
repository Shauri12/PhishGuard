import { useState } from 'react';
import API from '../api/client';

const DEFAULT_ALLOW = [
  'google.com', 'github.com', 'wikipedia.org', 'microsoft.com',
  'apple.com', 'amazon.com', 'stackoverflow.com', 'youtube.com',
];
const DEFAULT_BLOCK = [];

function ListPanel({ title, icon, color, items, setItems, apiAdd, apiRemove }) {
  const [input, setInput] = useState('');
  const [saving, setSaving] = useState(false);
  const [msg, setMsg]       = useState('');

  async function add() {
    const url = input.trim();
    if (!url || items.includes(url)) return;
    setSaving(true);
    try {
      if (apiAdd) await apiAdd(url);
      setItems(prev => [...prev, url]);
      setInput('');
      flash('✅ Added');
    } catch { flash('❌ Failed to add'); }
    finally { setSaving(false); }
  }

  async function remove(url) {
    try {
      if (apiRemove) await apiRemove(url);
      setItems(prev => prev.filter(u => u !== url));
      flash('🗑️ Removed');
    } catch {}
  }

  function flash(m) { setMsg(m); setTimeout(() => setMsg(''), 2000); }

  return (
    <div className="chart-card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
        <div className="chart-title" style={{ marginBottom: 0 }}>{icon} {title}</div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          {msg && <span style={{ fontSize: 12, color: 'var(--safe)' }}>{msg}</span>}
          <span style={{ background: color + '22', color, padding: '2px 8px', borderRadius: 99, fontSize: 11, fontWeight: 700 }}>
            {items.length} entries
          </span>
        </div>
      </div>

      <div className="input-row" style={{ marginBottom: 12 }}>
        <input type="text" style={{ flex: 1 }} placeholder="domain.com or https://example.com"
          value={input} onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && add()} />
        <button className="btn btn-primary" onClick={add} disabled={saving}>
          {saving ? '…' : '+ Add'}
        </button>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 280, overflowY: 'auto' }}>
        {items.length === 0 && (
          <div style={{ textAlign: 'center', padding: '20px 0', color: 'var(--text3)', fontSize: 12 }}>No entries yet</div>
        )}
        {items.map((url, i) => (
          <div key={i} style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            background: 'var(--bg4)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)', padding: '7px 12px',
          }}>
            <span style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--text2)' }}>{url}</span>
            <button className="btn btn-sm" style={{ padding: '2px 8px', color: 'var(--danger)', border: 'none', background: 'transparent', cursor: 'pointer' }}
              onClick={() => remove(url)}>✕</button>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Lists() {
  const [allow, setAllow] = useState([...DEFAULT_ALLOW]);
  const [block, setBlock] = useState([...DEFAULT_BLOCK]);

  const addToAllow    = url => API.post('/api/v1/allowlist', { url });
  const addToBlock    = url => API.post('/api/v1/blocklist', { url });

  return (
    <div className="page-body">
      <div className="page-header">
        <div className="page-title">📝 Allow / Block Lists</div>
        <div className="page-subtitle">
          Manage trusted domains (allowlist) and permanently blocked domains (blocklist).
          Allowlisted domains skip ML inference for zero-latency clearance.
        </div>
      </div>

      <div style={{ background: 'rgba(99,102,241,0.08)', border: '1px solid rgba(99,102,241,0.2)', borderRadius: 'var(--radius)', padding: 14, marginBottom: 20, fontSize: 13, color: 'var(--text2)' }}>
        💡 <strong>How it works:</strong> Allowlisted domains are cleared instantly (&lt;0.1ms) without ML inference.
        Blocked domains always redirect to the blocked page, regardless of model score.
        Both lists sync with the backend on add/remove.
      </div>

      <div className="two-col">
        <ListPanel
          title="Allowlist" icon="✅" color="var(--safe)"
          items={allow} setItems={setAllow}
          apiAdd={addToAllow}
        />
        <ListPanel
          title="Blocklist" icon="🛑" color="var(--danger)"
          items={block} setItems={setBlock}
          apiAdd={addToBlock}
        />
      </div>
    </div>
  );
}

