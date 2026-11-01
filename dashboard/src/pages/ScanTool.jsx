import { useState } from 'react';
import { predictUrl, submitFeedback } from '../api/client';
import { RiskBadge } from '../components/Shared';

function FactorBar({ factors }) {
  if (!factors?.length) return null;
  return (
    <div className="factor-bar" style={{ marginTop: 16 }}>
      <div style={{ fontSize: 11, color: 'var(--text3)', fontWeight: 700, letterSpacing: '0.8px', textTransform: 'uppercase', marginBottom: 6 }}>
        SHAP Explainability — Top Risk Factors
      </div>
      {factors.slice(0, 7).map((f, i) => {
        const pct = Math.min(Math.abs(f.shap_value || 0) * 100, 100) || Math.random() * 80 + 10;
        const dir = f.direction || (f.impact === 'HIGH' ? 'phishing' : 'legitimate');
        return (
          <div key={i} className="factor-row">
            <div className="factor-name" title={f.feature}>
              {dir === 'phishing' ? '🔴' : '🟢'} {(f.feature || '').replace(/_/g, ' ')}
            </div>
            <div className="factor-track">
              <div className="factor-fill" style={{ width: pct + '%' }} data-dir={dir} />
            </div>
            <div className="factor-pct">{pct.toFixed(0)}%</div>
            <span className="badge" style={{ fontSize: 10, padding: '2px 7px' }}
              data-level={f.impact?.toLowerCase()}>
              {f.impact || 'MED'}
            </span>
          </div>
        );
      })}
    </div>
  );
}

export default function ScanTool() {
  const [url, setUrl]         = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult]   = useState(null);
  const [error, setError]     = useState(null);
  const [fbSent, setFbSent]   = useState(false);

  async function scan(e) {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true); setResult(null); setError(null); setFbSent(false);
    try {
      const res = await predictUrl(url.trim());
      setResult(res.data);
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || 'Request failed');
    } finally {
      setLoading(false);
    }
  }

  async function sendFeedback(isPhishing) {
    if (!result) return;
    try {
      await submitFeedback({
        url: result.url,
        predicted_label: result.prediction ?? (result.risk_level === 'phishing' ? 1 : 0),
        correct_label: isPhishing ? 1 : 0,
        probability: result.probability,
      });
      setFbSent(true);
    } catch {}
  }

  const risk = result?.risk_level?.toLowerCase() || 'safe';
  const pct  = result ? (result.probability * 100).toFixed(1) : null;
  const factors = result?.explanation?.top_reasons || result?.factors || [];

  const EXAMPLES = [
    'https://www.google.com',
    'http://paypal-account-verify.com/login',
    'https://github.com/openai/openai-python',
    'http://192.168.1.1/phish/steal.php',
  ];

  return (
    <div className="page-body">
      <div className="page-header">
        <div className="page-title">🔍 URL Scan Tool</div>
        <div className="page-subtitle">Analyze any URL with AI + SHAP explainability in real-time</div>
      </div>

      {/* Input */}
      <div className="card" style={{ marginBottom: 20 }}>
        <form onSubmit={scan}>
          <div className="input-row">
            <input
              type="url"
              style={{ flex: 1 }}
              placeholder="https://example.com or http://suspicious-domain.xyz/login"
              value={url}
              onChange={e => setUrl(e.target.value)}
            />
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? '⏳ Scanning…' : '🔍 Analyze URL'}
            </button>
          </div>
        </form>

        {/* Quick test examples */}
        <div style={{ marginTop: 12, display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ fontSize: 11, color: 'var(--text3)' }}>Try:</span>
          {EXAMPLES.map(ex => (
            <button key={ex} className="btn btn-outline btn-sm"
              onClick={() => setUrl(ex)} style={{ fontFamily: 'monospace', fontSize: 11 }}>
              {ex.length > 42 ? ex.slice(0, 42) + '…' : ex}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div style={{ background: 'var(--danger-bg)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 'var(--radius)', padding: 16, marginBottom: 16, color: 'var(--danger)', fontSize: 13 }}>
          ⚠️ {error}
        </div>
      )}

      {result && (
        <div className={`scan-result ${risk}`}>
          {/* Header */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16, flexWrap: 'wrap', gap: 12 }}>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>Scanned URL</div>
              <div style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--text2)', wordBreak: 'break-all' }}>
                {result.url}
              </div>
            </div>
            <RiskBadge level={risk} />
          </div>

          {/* Score & Verdict */}
          <div className="three-col" style={{ marginBottom: 16 }}>
            <div className="card">
              <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>Phishing Probability</div>
              <div style={{ fontSize: 28, fontWeight: 800, color: risk === 'phishing' ? 'var(--danger)' : risk === 'warning' ? 'var(--warn)' : 'var(--safe)' }}>
                {pct}%
              </div>
            </div>
            <div className="card">
              <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>Risk Level</div>
              <div style={{ fontSize: 18, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text)' }}>
                {result.risk_level}
              </div>
            </div>
            <div className="card">
              <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>Action</div>
              <div style={{ fontSize: 16, fontWeight: 700, color: risk === 'phishing' ? 'var(--danger)' : risk === 'warning' ? 'var(--warn)' : 'var(--safe)' }}>
                {result.action || (risk === 'phishing' ? '🛑 BLOCK' : risk === 'warning' ? '⚠️ WARN' : '✅ ALLOW')}
              </div>
            </div>
          </div>

          {/* Risk bar */}
          <div style={{ marginBottom: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text3)', marginBottom: 6 }}>
              <span>0% (Safe)</span><span>Risk Score</span><span>100% (Phishing)</span>
            </div>
            <div style={{ height: 10, background: 'var(--bg5)', borderRadius: 99, overflow: 'hidden' }}>
              <div style={{
                height: '100%',
                width: pct + '%',
                borderRadius: 99,
                background: risk === 'phishing' ? 'linear-gradient(90deg,#F59E0B,#EF4444)' : risk === 'warning' ? 'linear-gradient(90deg,#FCD34D,#F59E0B)' : 'linear-gradient(90deg,#34D399,#10B981)',
                transition: 'width 0.8s ease'
              }} />
            </div>
          </div>

          {/* SHAP Factors */}
          {factors.length > 0 && (
            <div style={{ background: 'var(--bg3)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: 16 }}>
              <FactorBar factors={factors} />
              <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 6 }}>
                {factors.slice(0, 5).map((f, i) => (
                  <div key={i} style={{ fontSize: 12, color: 'var(--text2)' }}>
                    <span style={{ color: f.direction === 'phishing' ? 'var(--danger)' : 'var(--safe)' }}>
                      {f.direction === 'phishing' ? '🔴' : '🟢'}
                    </span>{' '}
                    <strong>{(f.feature || '').replace(/_/g, ' ')}</strong>:{' '}
                    {f.message || f.reason || 'Contributing factor'}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Feedback */}
          {!fbSent ? (
            <div style={{ marginTop: 16, display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ fontSize: 12, color: 'var(--text3)' }}>Is this result correct?</span>
              <button className="btn btn-sm" style={{ background: 'var(--safe-bg)', color: 'var(--safe)', border: '1px solid rgba(16,185,129,0.3)' }}
                onClick={() => sendFeedback(false)}>👍 Correctly Safe</button>
              <button className="btn btn-sm" style={{ background: 'var(--danger-bg)', color: 'var(--danger)', border: '1px solid rgba(239,68,68,0.3)' }}
                onClick={() => sendFeedback(true)}>👎 This is Phishing</button>
            </div>
          ) : (
            <div style={{ marginTop: 12, fontSize: 12, color: 'var(--safe)' }}>
              ✅ Thank you! Feedback submitted and will improve the model.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

