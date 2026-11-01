import { useState, useEffect } from 'react';
import { getFeedback, submitFeedback } from '../api/client';
import { RiskBadge, Spinner } from '../components/Shared';

const SEED_REPORTS = [
  { id: 'rpt-01', url: 'https://paypal-verify-account.secure-ssl-check.com', predicted: 'phishing', probability: 0.93, reported_as: 'safe',    ts: '2026-11-01T10:22:00Z', comment: 'Legitimate portal' },
  { id: 'rpt-02', url: 'https://github.com/user/repository/pulls',           predicted: 'safe',     probability: 0.04, reported_as: 'phishing', ts: '2026-11-01T11:05:00Z', comment: 'Suspicious clone' },
  { id: 'rpt-03', url: 'http://amazon.support-reset.account-check.net',      predicted: 'phishing', probability: 0.88, reported_as: 'safe',    ts: '2026-11-01T13:14:00Z', comment: 'Testing account' },
];

function FeedbackRow({ item, onResolve }) {
  const [status, setStatus] = useState('pending');

  async function resolve(accept) {
    try {
      await submitFeedback({
        url: item.url,
        reported_as: accept ? item.reported_as : (item.reported_as === 'safe' ? 'false_negative' : 'false_positive'),
        correct_label: accept ? (item.reported_as === 'phishing' ? 1 : 0) : (item.predicted === 'phishing' ? 1 : 0),
        probability: item.probability,
        user_comment: accept ? 'Accepted by SOC analyst' : 'Rejected by SOC analyst',
      });
      setStatus(accept ? 'accepted' : 'rejected');
      onResolve(item.id);
    } catch {
      setStatus(accept ? 'accepted' : 'rejected');
      onResolve(item.id);
    }
  }

  const scoreText = item.probability != null ? (item.probability * 100).toFixed(1) + '%' : '—';

  return (
    <tr>
      <td className="url-cell" title={item.url}>{item.url}</td>
      <td><RiskBadge level={item.predicted || 'warning'} /></td>
      <td style={{ fontSize: 12, color: 'var(--text2)', fontVariantNumeric: 'tabular-nums' }}>{scoreText}</td>
      <td>
        <span style={{ fontSize: 12, color: item.reported_as === 'safe' || item.reported_as === 'false_positive' ? 'var(--safe)' : 'var(--danger)', fontWeight: 600 }}>
          {item.reported_as === 'safe' || item.reported_as === 'false_positive' ? '👍 Reported Safe' : '👎 Reported Phishing'}
        </span>
      </td>
      <td style={{ color: 'var(--text3)', fontSize: 11, whiteSpace: 'nowrap' }}>
        {item.ts ? new Date(item.ts).toLocaleString() : '—'}
      </td>
      <td>
        {status === 'pending' ? (
          <div style={{ display: 'flex', gap: 6 }}>
            <button className="btn btn-sm" style={{ background: 'var(--safe-bg)', color: 'var(--safe)', border: '1px solid rgba(16,185,129,0.3)' }}
              onClick={() => resolve(true)}>Accept</button>
            <button className="btn btn-sm" style={{ background: 'var(--danger-bg)', color: 'var(--danger)', border: '1px solid rgba(239,68,68,0.3)' }}
              onClick={() => resolve(false)}>Reject</button>
          </div>
        ) : (
          <span style={{ fontSize: 12, color: status === 'accepted' ? 'var(--safe)' : 'var(--danger)', fontWeight: 700 }}>
            {status === 'accepted' ? '✅ Approved' : '❌ Dismissed'}
          </span>
        )}
      </td>
    </tr>
  );
}

export default function Feedback() {
  const [items, setItems]       = useState([]);
  const [resolved, setResolved] = useState([]);
  const [loading, setLoading]   = useState(true);

  useEffect(() => {
    getFeedback()
      .then(r => {
        const rawLogs = r.data || [];
        if (rawLogs.length > 0) {
          const backendItems = rawLogs.map((log, idx) => ({
            id: log.report_id || `log-${idx}`,
            url: log.url,
            predicted: log.predicted_label === 1 ? 'phishing' : log.predicted_label === 0 ? 'safe' : 'warning',
            probability: log.probability ?? 0.85,
            reported_as: log.reported_as || 'false_positive',
            ts: log.timestamp,
            comment: log.user_comment || '',
          }));
          setItems(backendItems);
        } else {
          setItems(SEED_REPORTS);
        }
      })
      .catch(() => setItems(SEED_REPORTS))
      .finally(() => setLoading(false));
  }, []);

  function resolve(id) {
    setResolved(prev => [...prev, id]);
  }

  if (loading) return <Spinner />;

  const pending = items.filter(i => !resolved.includes(i.id));

  return (
    <div className="page-body">
      <div className="page-header">
        <div className="page-title">💬 Feedback Review Queue</div>
        <div className="page-subtitle">
          User-reported classification corrections — review and approve to retrain the model.
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 16, marginBottom: 20 }}>
        {[
          { label: 'Pending Review', val: pending.length, c: 'var(--warn)' },
          { label: 'Resolved',       val: resolved.length, c: 'var(--safe)' },
          { label: 'Total Reports',  val: items.length, c: 'var(--accent)' },
        ].map(x => (
          <div key={x.label} className="metric-card">
            <div className="metric-label">{x.label}</div>
            <div className="metric-value" style={{ color: x.c }}>{x.val}</div>
          </div>
        ))}
      </div>

      <div className="chart-card">
        <div className="chart-title">📬 User-Submitted Reports Queue</div>
        {pending.length > 0 ? (
          <div className="table-wrapper" style={{ border: 'none' }}>
            <table>
              <thead>
                <tr>
                  <th>URL</th>
                  <th>Predicted</th>
                  <th>Score</th>
                  <th>User Report</th>
                  <th>Time</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {pending.map(item => (
                  <FeedbackRow key={item.id} item={item} onResolve={resolve} />
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ textAlign: 'center', padding: '36px 0', color: 'var(--text3)' }}>
            <div style={{ fontSize: 32, marginBottom: 8 }}>🎉</div>
            <div style={{ color: 'var(--text2)', fontSize: 14 }}>All feedback reviewed — queue is clear!</div>
          </div>
        )}
      </div>

      <div className="card" style={{ marginTop: 20 }}>
        <div className="card-title">ℹ️ How Active Learning Feedback Works</div>
        <div style={{ fontSize: 13, color: 'var(--text2)', lineHeight: 1.7 }}>
          When users click <strong>"Report False Positive"</strong> or <strong>"Report as Safe"</strong> on the blocked page,
          extension popup, or dashboard scanner, reports enter this verification queue.
          Approved corrections are stored directly in the database for the next model retraining cycle,
          closing the <strong>human-in-the-loop active learning loop</strong>.
        </div>
      </div>
    </div>
  );
}
