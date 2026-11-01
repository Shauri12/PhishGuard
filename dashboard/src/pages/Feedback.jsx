import { useState } from 'react';
import { submitFeedback } from '../api/client';
import { RiskBadge } from '../components/Shared';

const MOCK_PENDING = [
  { id: 1, url: 'https://paypal-verify-account.secure-ssl-check.com', predicted: 'phishing', probability: 0.93, reported_as: 'safe',    ts: '2026-11-01T10:22:00Z' },
  { id: 2, url: 'https://github.com/user/repository/pulls',           predicted: 'safe',     probability: 0.04, reported_as: 'phishing', ts: '2026-11-01T11:05:00Z' },
  { id: 3, url: 'http://amazon.support-reset.account-check.net',      predicted: 'phishing', probability: 0.88, reported_as: 'safe',    ts: '2026-11-01T13:14:00Z' },
];

function FeedbackRow({ item, onResolve }) {
  const [status, setStatus] = useState('pending');

  async function resolve(accept) {
    try {
      await submitFeedback({
        url: item.url,
        predicted_label: item.predicted === 'phishing' ? 1 : 0,
        correct_label: accept ? (item.reported_as === 'phishing' ? 1 : 0) : (item.predicted === 'phishing' ? 1 : 0),
        probability: item.probability,
      });
      setStatus(accept ? 'accepted' : 'rejected');
      onResolve(item.id);
    } catch { setStatus('error'); }
  }

  return (
    <tr>
      <td className="url-cell" title={item.url}>{item.url}</td>
      <td><RiskBadge level={item.predicted} /></td>
      <td style={{ fontSize: 12, color: 'var(--text2)' }}>{(item.probability * 100).toFixed(1)}%</td>
      <td>
        <span style={{ fontSize: 12, color: item.reported_as === 'safe' ? 'var(--safe)' : 'var(--danger)', fontWeight: 600 }}>
          {item.reported_as === 'safe' ? '👍 Reported Safe' : '👎 Reported Phishing'}
        </span>
      </td>
      <td style={{ color: 'var(--text3)', fontSize: 11 }}>{new Date(item.ts).toLocaleString()}</td>
      <td>
        {status === 'pending' ? (
          <div style={{ display: 'flex', gap: 6 }}>
            <button className="btn btn-sm" style={{ background: 'var(--safe-bg)', color: 'var(--safe)', border: '1px solid rgba(16,185,129,0.3)' }}
              onClick={() => resolve(true)}>Accept</button>
            <button className="btn btn-sm" style={{ background: 'var(--danger-bg)', color: 'var(--danger)', border: '1px solid rgba(239,68,68,0.3)' }}
              onClick={() => resolve(false)}>Reject</button>
          </div>
        ) : (
          <span style={{ fontSize: 12, color: status === 'accepted' ? 'var(--safe)' : status === 'rejected' ? 'var(--danger)' : 'var(--text3)', fontWeight: 600 }}>
            {status === 'accepted' ? '✅ Accepted' : status === 'rejected' ? '❌ Rejected' : '⚠️ Error'}
          </span>
        )}
      </td>
    </tr>
  );
}

export default function Feedback() {
  const [items, setItems] = useState(MOCK_PENDING);
  const [resolved, setResolved] = useState([]);

  function resolve(id) {
    setResolved(prev => [...prev, id]);
  }

  const pending = items.filter(i => !resolved.includes(i.id));

  return (
    <div className="page-body">
      <div className="page-header">
        <div className="page-title">💬 Feedback Review</div>
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
        <div className="chart-title">📬 Pending User Reports</div>
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
        <div className="card-title">ℹ️ How Feedback Works</div>
        <div style={{ fontSize: 13, color: 'var(--text2)', lineHeight: 1.7 }}>
          When users click <strong>"Report False Positive"</strong> or <strong>"Report as Safe"</strong> on the blocked/warning page or popup,
          those reports are submitted to <code style={{ background: 'var(--bg4)', padding: '1px 5px', borderRadius: 4 }}>/api/v1/feedback</code>.
          After reviewing, accepting a report stores the corrected label in the database for use in the next model retraining cycle,
          closing the <strong>active learning loop</strong>.
        </div>
      </div>
    </div>
  );
}

