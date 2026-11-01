// PhishGuard Popup JS

const $ = id => document.getElementById(id);

// ─── State ────────────────────────────────────────────────────────────────────
let currentResult = null;
let currentUrl = null;
let settings = { autoBlock: true, notifications: true, threshold_warning: 0.5, threshold_block: 0.85 };

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadSettings();
  loadResult();
  bindUI();
  $('footer-ts').textContent = new Date().toLocaleTimeString();
});

// ─── Fetch result from background ────────────────────────────────────────────
function loadResult() {
  showState('loading');
  chrome.runtime.sendMessage({ type: 'GET_RESULT' }, (resp) => {
    if (chrome.runtime.lastError || !resp) {
      showState('error');
      return;
    }
    const { result, cached } = resp;
    if (!result || result.error) {
      showState('error');
      return;
    }
    currentResult = result;
    currentUrl    = result.url || result.original_url || '';
    renderResult(result, cached);
  });
}

// ─── Render main result ───────────────────────────────────────────────────────
function renderResult(r, cached) {
  showState('result');

  const prob  = r.probability ?? 0;
  const risk  = r.risk_level  ?? 'safe';
  const pct   = Math.round(prob * 100);

  // Gauge
  animateGauge(prob, risk);
  $('gauge-pct').textContent = `${pct}%`;

  // Risk badge
  const badge = $('risk-badge');
  badge.textContent = risk.toUpperCase();
  badge.className = `risk-badge risk-${risk}`;

  // URL
  const urlStr = r.url || r.original_url || '';
  currentUrl = urlStr;
  $('display-url').textContent = urlStr;
  $('display-url').title = urlStr;

  // Metrics
  $('metric-confidence').textContent = `${pct}%`;
  $('metric-cached').textContent = cached ? 'Cached' : 'Live';

  // SHAP factors
  renderShap(r.factors || r.top_factors || []);
}

// ─── Gauge animation ──────────────────────────────────────────────────────────
function animateGauge(prob, risk) {
  const arc    = $('gauge-arc');
  const total  = 267;
  const offset = total - (total * prob);

  // Color gradient selection
  const grad = risk === 'safe' ? 'gaugeGradSafe' : risk === 'warning' ? 'gaugeGradWarn' : 'gaugeGradDanger';
  arc.setAttribute('stroke', `url(#${grad})`);

  // Smooth animation
  arc.style.transition = 'stroke-dashoffset 0.8s cubic-bezier(0.4,0,0.2,1)';
  arc.setAttribute('stroke-dashoffset', offset);
}

// ─── SHAP rendering ───────────────────────────────────────────────────────────
function renderShap(factors) {
  const list = $('shap-list');
  list.innerHTML = '';

  if (!factors || factors.length === 0) {
    list.innerHTML = '<p style="color:var(--text3);font-size:11px;text-align:center">No explanation data available</p>';
    return;
  }

  const maxAbs = Math.max(...factors.map(f => Math.abs(f.shap_value ?? f.contribution ?? 0)), 0.001);

  factors.slice(0, 8).forEach(f => {
    const val  = f.shap_value ?? f.contribution ?? 0;
    const name = (f.feature || f.name || '').replace(/_/g, ' ');
    const pct  = Math.round((Math.abs(val) / maxAbs) * 100);
    const dir  = val >= 0 ? 'positive' : 'negative';
    const sign = val >= 0 ? '+' : '';

    const item = document.createElement('div');
    item.className = `shap-item shap-${dir}`;
    item.innerHTML = `
      <div class="shap-item-header">
        <span class="shap-feature">${name}</span>
        <span class="shap-value">${sign}${val.toFixed(3)}</span>
      </div>
      <div class="shap-bar-track">
        <div class="shap-bar-fill" style="width:0%"></div>
      </div>
    `;
    list.appendChild(item);
    // Animate bar
    requestAnimationFrame(() => {
      item.querySelector('.shap-bar-fill').style.width = `${pct}%`;
    });
  });
}

// ─── UI Bindings ──────────────────────────────────────────────────────────────
function bindUI() {
  // Accordion toggles
  ['toggle-shap', 'toggle-feedback'].forEach(id => {
    $(id).addEventListener('click', () => {
      const panelId = id === 'toggle-shap' ? 'shap-panel' : 'feedback-panel';
      const btn = $(id);
      const panel = $(panelId);
      btn.classList.toggle('open');
      panel.classList.toggle('hidden');
    });
  });

  // Reanalyze
  $('btn-reanalyze').addEventListener('click', () => {
    showState('loading');
    chrome.runtime.sendMessage({ type: 'REANALYZE' }, (resp) => {
      if (!resp || resp.result?.error) { showState('error'); return; }
      currentResult = resp.result;
      renderResult(resp.result, false);
    });
  });

  // Retry (error state)
  $('btn-retry').addEventListener('click', loadResult);

  // Settings open/close
  $('btn-settings').addEventListener('click', () => $('settings-panel').classList.remove('hidden'));
  $('close-settings').addEventListener('click', () => $('settings-panel').classList.add('hidden'));

  // Settings inputs
  $('set-warn-thresh').addEventListener('input', e => $('warn-val').textContent = `${e.target.value}%`);
  $('set-block-thresh').addEventListener('input', e => $('block-val').textContent = `${e.target.value}%`);

  $('save-settings').addEventListener('click', saveSettings);

  // Feedback buttons
  ['fb-safe', 'fb-phish'].forEach(id => {
    $(id).addEventListener('click', () => sendFeedback($(id).dataset.label));
  });
}

// ─── Show State ───────────────────────────────────────────────────────────────
function showState(state) {
  $('state-loading').classList.toggle('hidden', state !== 'loading');
  $('state-error').classList.toggle('hidden', state !== 'error');
  $('state-result').classList.toggle('hidden', state !== 'result');
}

// ─── Feedback ─────────────────────────────────────────────────────────────────
function sendFeedback(label) {
  $('fb-safe').classList.remove('selected');
  $('fb-phish').classList.remove('selected');
  $(label === 'safe' ? 'fb-safe' : 'fb-phish').classList.add('selected');

  chrome.runtime.sendMessage({
    type: 'FEEDBACK',
    payload: {
      url: currentUrl,
      correct_label: label === 'safe' ? 0 : 1,
      predicted_label: currentResult?.prediction ?? -1,
      probability: currentResult?.probability ?? 0,
    }
  }, () => {
    $('feedback-thanks').classList.remove('hidden');
    setTimeout(() => $('feedback-thanks').classList.add('hidden'), 3000);
  });
}

// ─── Settings persistence ─────────────────────────────────────────────────────
function loadSettings() {
  chrome.storage.local.get('settings', (data) => {
    if (data.settings) {
      settings = data.settings;
      $('set-autoblock').checked = settings.autoBlock;
      $('set-notifs').checked    = settings.notifications;
      const warnPct  = Math.round(settings.threshold_warning * 100);
      const blockPct = Math.round(settings.threshold_block   * 100);
      $('set-warn-thresh').value  = warnPct;
      $('set-block-thresh').value = blockPct;
      $('warn-val').textContent   = `${warnPct}%`;
      $('block-val').textContent  = `${blockPct}%`;
    }
  });
}

function saveSettings() {
  settings = {
    autoBlock:           $('set-autoblock').checked,
    notifications:       $('set-notifs').checked,
    threshold_warning:   parseInt($('set-warn-thresh').value) / 100,
    threshold_block:     parseInt($('set-block-thresh').value) / 100,
  };
  chrome.storage.local.set({ settings }, () => {
    $('settings-panel').classList.add('hidden');
  });
}
