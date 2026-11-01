// PhishGuard - Settings Page Logic
document.addEventListener('DOMContentLoaded', () => {
  // Navigation
  function showPage(name) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const targetPage = document.getElementById('page-' + name);
    const targetNav = document.getElementById('nav-' + name);
    if (targetPage) targetPage.classList.add('active');
    if (targetNav) targetNav.classList.add('active');
  }

  document.querySelectorAll('.nav-item[data-tab]').forEach(item => {
    item.addEventListener('click', () => {
      showPage(item.getAttribute('data-tab'));
    });
  });

  // Sliders display
  const threshWarn = document.getElementById('thresh-warn');
  const threshWarnVal = document.getElementById('thresh-warn-val');
  if (threshWarn && threshWarnVal) {
    threshWarn.addEventListener('input', (e) => {
      threshWarnVal.textContent = e.target.value + '%';
    });
  }

  const threshBlock = document.getElementById('thresh-block');
  const threshBlockVal = document.getElementById('thresh-block-val');
  if (threshBlock && threshBlockVal) {
    threshBlock.addEventListener('input', (e) => {
      threshBlockVal.textContent = e.target.value + '%';
    });
  }

  // Load stored settings
  chrome.storage.local.get(['settings','allowlist','blocklist','scanHistory'], function(data) {
    const s = data.settings || {};
    if (s.autoBlock !== undefined && document.getElementById('set-autoblock')) {
      document.getElementById('set-autoblock').checked = s.autoBlock;
    }
    if (s.notifications !== undefined && document.getElementById('set-notifs')) {
      document.getElementById('set-notifs').checked = s.notifications;
    }
    if (s.threshold_warning && threshWarn && threshWarnVal) {
      const w = Math.round(s.threshold_warning * 100);
      threshWarn.value = w;
      threshWarnVal.textContent = w + '%';
    }
    if (s.threshold_block && threshBlock && threshBlockVal) {
      const b = Math.round(s.threshold_block * 100);
      threshBlock.value = b;
      threshBlockVal.textContent = b + '%';
    }

    const allow = data.allowlist || [];
    const allowInput = document.getElementById('allowlist-input');
    if (allowInput) allowInput.value = allow.join('\n');

    const block = data.blocklist || [];
    const blockInput = document.getElementById('blocklist-input');
    if (blockInput) blockInput.value = block.join('\n');

    const history = data.scanHistory || [];
    const histCount = document.getElementById('history-count');
    if (histCount) histCount.textContent = history.length;
    renderHistory(history);
    computeStats(history);
  });

  // Save Settings
  function saveSettings() {
    const autoBlock = document.getElementById('set-autoblock') ? document.getElementById('set-autoblock').checked : true;
    const notifs = document.getElementById('set-notifs') ? document.getElementById('set-notifs').checked : true;
    const warnVal = threshWarn ? parseInt(threshWarn.value) / 100 : 0.50;
    const blockVal = threshBlock ? parseInt(threshBlock.value) / 100 : 0.85;

    const settings = {
      autoBlock: autoBlock,
      notifications: notifs,
      threshold_warning: warnVal,
      threshold_block: blockVal,
    };
    chrome.storage.local.set({ settings: settings }, () => showToast('Settings saved successfully!'));
  }

  const btnSaveSettings = document.getElementById('btn-save-settings');
  if (btnSaveSettings) btnSaveSettings.addEventListener('click', saveSettings);

  const btnReset = document.getElementById('btn-reset-defaults');
  if (btnReset) {
    btnReset.addEventListener('click', () => {
      if (document.getElementById('set-autoblock')) document.getElementById('set-autoblock').checked = true;
      if (document.getElementById('set-notifs')) document.getElementById('set-notifs').checked = true;
      if (threshWarn) threshWarn.value = 50;
      if (threshWarnVal) threshWarnVal.textContent = '50%';
      if (threshBlock) threshBlock.value = 85;
      if (threshBlockVal) threshBlockVal.textContent = '85%';
      saveSettings();
    });
  }

  // Lists
  function saveList(type) {
    const input = document.getElementById(type + 'list-input');
    if (!input) return;
    const items = input.value.split('\n').map(s => s.trim()).filter(Boolean);
    const obj = {};
    obj[type + 'list'] = items;
    chrome.storage.local.set(obj, () => showToast(type.charAt(0).toUpperCase() + type.slice(1) + 'list updated!'));
  }

  const btnSaveAllow = document.getElementById('btn-save-allow');
  if (btnSaveAllow) btnSaveAllow.addEventListener('click', () => saveList('allow'));

  const btnClearAllow = document.getElementById('btn-clear-allow');
  if (btnClearAllow) {
    btnClearAllow.addEventListener('click', () => {
      const input = document.getElementById('allowlist-input');
      if (input) input.value = '';
      saveList('allow');
    });
  }

  const btnSaveBlock = document.getElementById('btn-save-block');
  if (btnSaveBlock) btnSaveBlock.addEventListener('click', () => saveList('block'));

  const btnClearBlock = document.getElementById('btn-clear-block');
  if (btnClearBlock) {
    btnClearBlock.addEventListener('click', () => {
      const input = document.getElementById('blocklist-input');
      if (input) input.value = '';
      saveList('block');
    });
  }

  // History & Stats
  function renderHistory(history) {
    const tbody = document.getElementById('history-tbody');
    if (!tbody) return;
    if (!history.length) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;padding:30px;color:var(--text3)">No scan history yet</td></tr>';
      return;
    }
    tbody.innerHTML = history.slice().reverse().slice(0, 100).map(function(h) {
      const risk = h.risk_level || 'safe';
      const score = h.probability != null ? Math.round(h.probability * 100) + '%' : '-';
      const time = h.ts ? new Date(h.ts).toLocaleTimeString() : '-';
      return '<tr>' +
        '<td class="url-cell" title="' + h.url + '">' + h.url + '</td>' +
        '<td><span class="risk-chip ' + risk + '">' + risk.toUpperCase() + '</span></td>' +
        '<td>' + score + '</td>' +
        '<td>' + time + '</td>' +
      '</tr>';
    }).join('');
  }

  function computeStats(history) {
    const total = history.length;
    const safe = history.filter(h => h.risk_level === 'safe').length;
    const warn = history.filter(h => h.risk_level === 'warning').length;
    const blocked = history.filter(h => h.risk_level === 'phishing').length;
    if (document.getElementById('stat-total')) document.getElementById('stat-total').textContent = total;
    if (document.getElementById('stat-safe')) document.getElementById('stat-safe').textContent = safe;
    if (document.getElementById('stat-warn')) document.getElementById('stat-warn').textContent = warn;
    if (document.getElementById('stat-blocked')) document.getElementById('stat-blocked').textContent = blocked;
  }

  const btnClearHistory = document.getElementById('btn-clear-history');
  if (btnClearHistory) {
    btnClearHistory.addEventListener('click', () => {
      if (confirm('Clear all scan history?')) {
        chrome.storage.local.set({ scanHistory: [] }, function() {
          renderHistory([]);
          computeStats([]);
          const histCount = document.getElementById('history-count');
          if (histCount) histCount.textContent = '0';
          showToast('Scan history cleared');
        });
      }
    });
  }

  const btnExportHistory = document.getElementById('btn-export-history');
  if (btnExportHistory) {
    btnExportHistory.addEventListener('click', () => {
      chrome.storage.local.get('scanHistory', function(data) {
        const rows = (data.scanHistory || []);
        const csv = 'URL,Risk,Score,Timestamp\n' +
          rows.map(function(h) {
            return ['"' + (h.url||'').replace(/"/g, '""') + '"', h.risk_level, h.probability, h.ts].join(',');
          }).join('\n');
        const blob = new Blob([csv], { type: 'text/csv' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'phishguard_history.csv';
        a.click();
      });
    });
  }

  // Backend Health Check
  fetch('http://127.0.0.1:8000/health')
    .then(r => r.json())
    .then(function(d) {
      const el = document.getElementById('backend-status');
      if (el) {
        el.textContent = 'Online (' + (d.status || 'OK') + ')';
        el.style.color = 'var(--safe)';
      }
    })
    .catch(function() {
      const el = document.getElementById('backend-status');
      if (el) {
        el.textContent = 'Offline';
        el.style.color = 'var(--danger)';
      }
    });

  // Toast
  function showToast(msg) {
    const t = document.getElementById('toast');
    if (!t) return;
    t.textContent = msg || 'Saved!';
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 2500);
  }
});
