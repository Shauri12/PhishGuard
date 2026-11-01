import { NavLink } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { checkHealth } from '../api/client';

const NAV = [
  { to: '/',          icon: '📊', label: 'Overview'   },
  { to: '/scan',      icon: '🔍', label: 'Scan Tool'  },
  { to: '/history',   icon: '📋', label: 'Detection History' },
  { to: '/analytics', icon: '📈', label: 'Analytics'  },
  { to: '/lists',     icon: '📝', label: 'Allow / Block Lists' },
  { to: '/feedback',  icon: '💬', label: 'Feedback'   },
];

export default function Sidebar() {
  const [status, setStatus] = useState('checking');

  useEffect(() => {
    checkHealth()
      .then(() => setStatus('online'))
      .catch(() => setStatus('offline'));
  }, []);

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-icon">🛡️</div>
        <div>
          <div className="logo-text">PhishGuard</div>
          <div style={{ fontSize: 10, color: 'var(--text3)', marginTop: 1 }}>SOC Dashboard</div>
        </div>
      </div>

      <nav className="nav">
        <div className="nav-section-label">Navigation</div>
        {NAV.map(n => (
          <NavLink
            key={n.to}
            to={n.to}
            end={n.to === '/'}
            className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
          >
            <span className="ni-icon">{n.icon}</span>
            {n.label}
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
          <span className={`status-dot ${status}`} />
          <span>Backend {status === 'online' ? 'Online' : status === 'offline' ? 'Offline' : 'Checking…'}</span>
        </div>
        <div style={{ color: 'var(--text4)', fontSize: 10 }}>PhishGuard v1.0 · XGBoost + SHAP</div>
      </div>
    </aside>
  );
}

