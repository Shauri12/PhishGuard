// PhishGuard - Settings Page Logic
document.addEventListener('DOMContentLoaded', () => {
  // ── Navigation ─────────────────────────────────────────────────────────────
  function showPage(name) {
    if (!name) return;
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const targetPage = document.getElementById('page-' + name);
    const targetNav = document.getElementById('nav-' + name);
    if (targetPage) targetPage.classList.add('active');
    if (targetNav) targetNav.classList.add('active');
  }

  document.querySelectorAll('.nav-item[data-tab]').forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      showPage(item.getAttribute('data-tab'));
    });
  });

  // ── Sliders dynamic display ────────────────────────────────────────────────
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

  // ── Load stored settings & lists ───────────────────────────────────────────
  chrome.storage.local.get(['settings', 'allowlist', 'blocklist', 'scanHistory'], function(data) {
    const s = data.settings || {};
    if (s.autoBlock !== undefined && document.getElementById('set-autoblock')) {
      document.getElementById('set-autoblock').checked = s.autoBlock;
    }
    if (s.banners !== undefined && document.getElementById('set-banners')) {
      document.getElementById('set-banners').checked = s.banners;
    }
    if (s.notifications !== undefined && document.getElementById('set-notifs')) {
      document.getElementById('set-notifs').checked = s.notifications;
    }
    if (s.realtime !== undefined && document.getElementById('set-realtime')) {
      document.getElementById('set-realtime').checked = s.realtime;
    }
    if (s.cacheMinutes && document.getElementById('set-cache')) {
      document.getElementById('set-cache').value = s.cacheMinutes;
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

  // ── Save Settings ──────────────────────────────────────────────────────────
  function saveSettings() {
    const autoBlock = document.getElementById('set-autoblock') ? document.getElementById('set-autoblock').checked : true;
    const banners   = document.getElementById('set-banners')   ? document.getElementById('set-banners').checked   : true;
    const notifs    = document.getElementById('set-notifs')    ? document.getElementById('set-notifs').checked    : true;
    const realtime  = document.getElementById('set-realtime')  ? document.getElementById('set-realtime').checked  : true;
    const cacheM    = document.getElementById('set-cache')     ? parseInt(document.getElementById('set-cache').value) : 5;
    const warnVal   = threshWarn  ? parseInt(threshWarn.value)  / 100 : 0.50;
    const blockVal  = threshBlock ? parseInt(threshBlock.value) / 100 : 0.85;

    const settings = {
      autoBlock: autoBlock,
      banners: banners,
      notifications: notifs,
      realtime: realtime,
      cacheMinutes: cacheM,
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
      if (document.getElementById('set-banners')) document.getElementById('set-banners').checked = true;
      if (document.getElementById('set-notifs')) document.getElementById('set-notifs').checked = true;
      if (document.getElementById('set-realtime')) document.getElementById('set-realtime').checked = true;
      if (document.getElementById('set-cache')) document.getElementById('set-cache').value = 5;
      if (threshWarn) threshWarn.value = 50;
      if (threshWarnVal) threshWarnVal.textContent = '50%';
      if (threshBlock) threshBlock.value = 85;
      if (threshBlockVal) threshBlockVal.textContent = '85%';
      saveSettings();
    });
  }

  // ── Lists Management ───────────────────────────────────────────────────────
  function saveList(type) {
    const input = document.getElementById(type + 'list-input');
    if (!input) return;
    const items = input.value.split('\n')
      .map(s => s.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0])
      .filter(Boolean);
    const obj = {};
    obj[type + 'list'] = [...new Set(items)];
    chrome.storage.local.set(obj, () => {
      input.value = obj[type + 'list'].join('\n');
      showToast(type.charAt(0).toUpperCase() + type.slice(1) + 'list updated (' + obj[type + 'list'].length + ' domains)');
    });
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

  // ── History & Stats ────────────────────────────────────────────────────────
  function renderHistory(history) {
    const tbody = document.getElementById('history-tbody');
    if (!tbody) return;
    if (!history.length) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;padding:30px;color:var(--text3)">No scan history yet</td></tr>';
      return;
    }
    tbody.innerHTML = history.slice().reverse().slice(0, 100).map(function(h) {
      const rawRisk = (h.risk_level || 'safe').toLowerCase();
      const risk = (rawRisk === 'blocked' || rawRisk === 'dangerous') ? 'phishing' : rawRisk;
      const score = h.probability != null ? Math.round(h.probability * 100) + '%' : '-';
      const time = h.ts ? new Date(h.ts).toLocaleTimeString() : (h.timestamp ? new Date(h.timestamp).toLocaleTimeString() : '-');
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
    const safe = history.filter(h => (h.risk_level||'').toLowerCase() === 'safe').length;
    const warn = history.filter(h => ['warning', 'suspicious'].includes((h.risk_level||'').toLowerCase())).length;
    const blocked = history.filter(h => ['phishing', 'blocked', 'dangerous'].includes((h.risk_level||'').toLowerCase())).length;
    if (document.getElementById('stat-total'))   document.getElementById('stat-total').textContent   = total;
    if (document.getElementById('stat-safe'))    document.getElementById('stat-safe').textContent    = safe;
    if (document.getElementById('stat-warn'))    document.getElementById('stat-warn').textContent    = warn;
    if (document.getElementById('stat-blocked')) document.getElementById('stat-blocked').textContent = blocked;
  }

  const btnClearHistory = document.getElementById('btn-clear-history');
  if (btnClearHistory) {
    btnClearHistory.addEventListener('click', () => {
      if (confirm('Clear all local scan history?')) {
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
            return ['"' + (h.url||'').replace(/"/g, '""') + '"', h.risk_level, h.probability, h.ts || h.timestamp].join(',');
          }).join('\n');
        const blob = new Blob([csv], { type: 'text/csv' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'phishguard_history_' + Date.now() + '.csv';
        a.click();
      });
    });
  }

  // ── Backend Health Check ───────────────────────────────────────────────────
  function checkBackend() {
    fetch('http://127.0.0.1:8000/api/v1/health')
      .then(r => r.json())
      .then(function(d) {
        const el = document.getElementById('backend-status');
        if (el) {
          el.textContent = 'Online (' + (d.status || 'OK') + ' · ' + (d.features_count || 25) + ' features)';
          el.style.color = 'var(--safe)';
        }
      })
      .catch(function() {
        // Fallback to root /health
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
      });
  }
  checkBackend();

  // ── Toast Notification ─────────────────────────────────────────────────────
  function showToast(msg) {
    const t = document.getElementById('toast');
    if (!t) return;
    t.textContent = msg || 'Saved!';
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 2500);
  }
});
