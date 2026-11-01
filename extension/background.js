// PhishGuard - Background Service Worker (Manifest V3)

const API_BASE = 'http://127.0.0.1:8000/api/v1';
const CACHE_TTL = 5 * 60 * 1000;
const urlCache = new Map();

const BADGE = {
  safe:     { color: '#00C896', text: 'OK' },
  warning:  { color: '#F59E0B', text: '!' },
  phishing: { color: '#EF4444', text: 'X' },
  loading:  { color: '#6366F1', text: '...' },
  error:    { color: '#94A3B8', text: '?' },
};

function setBadge(tabId, type) {
  const b = BADGE[type] || BADGE.error;
  chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
  chrome.action.setBadgeText({ tabId, text: b.text });
}

// Normalize API response fields to what the popup expects
// API returns: { phishing_probability, action, verdict, explanation, risk_score }
// Popup needs: { probability, risk_level, prediction, factors, url }
function normalizeResponse(raw, url) {
  const prob = raw.phishing_probability != null ? raw.phishing_probability : (raw.probability != null ? raw.probability : 0);

  const action = (raw.action || '').toUpperCase();
  let risk_level;
  if (raw.is_whitelisted) {
    risk_level = 'safe';
  } else if (action === 'BLOCK') {
    risk_level = 'phishing';
  } else if (action === 'WARN') {
    risk_level = 'warning';
  } else if (action === 'ALLOW') {
    risk_level = 'safe';
  } else {
    if (prob >= 0.85) risk_level = 'phishing';
    else if (prob >= 0.5) risk_level = 'warning';
    else risk_level = 'safe';
  }

  const explanations = raw.explanation || raw.factors || [];
  const factors = explanations.map(function(e) {
    const isPhishing = e.direction === 'phishing';
    const magnitude = e.impact === 'HIGH' ? 0.35 : e.impact === 'MEDIUM' ? 0.18 : 0.07;
    return {
      feature: e.feature || e.name || '',
      shap_value: isPhishing ? magnitude : -magnitude,
      direction: e.direction,
      message: e.message || '',
      value: e.value,
      impact: e.impact,
    };
  });

  return {
    url: url,
    probability: prob,
    risk_score: raw.risk_score != null ? raw.risk_score : Math.round(prob * 100),
    risk_level: risk_level,
    prediction: risk_level === 'safe' ? 0 : 1,
    verdict: raw.verdict || risk_level.toUpperCase(),
    is_whitelisted: raw.is_whitelisted || false,
    factors: factors,
    latency_ms: raw.latency_ms || 0,
    timestamp: raw.timestamp || new Date().toISOString(),
  };
}

async function analyzeUrl(url, tabId) {
  const now = Date.now();
  const cached = urlCache.get(url);
  if (cached && (now - cached.ts) < CACHE_TTL) {
    applyResult(tabId, url, cached.data);
    return cached.data;
  }

  // Check local allowlist & blocklist before API
  const stored = await new Promise(res => chrome.storage.local.get(['allowlist', 'blocklist', 'settings'], res));
  let hostname = '';
  try { hostname = new URL(url).hostname.replace(/^www\./, '').toLowerCase(); } catch(e) {}

  const allowlist = stored.allowlist || [];
  const isAllowlisted = allowlist.some(d => hostname === d || hostname.endsWith('.' + d));
  if (isAllowlisted) {
    const safeData = {
      url: url,
      probability: 0.0,
      risk_score: 0,
      risk_level: 'safe',
      prediction: 0,
      verdict: 'SAFE (Allowlist)',
      is_whitelisted: true,
      factors: [{ feature: 'custom_allowlist', impact: 'HIGH', direction: 'legitimate', message: 'Domain in your trusted allowlist' }],
      latency_ms: 0,
      timestamp: new Date().toISOString()
    };
    applyResult(tabId, url, safeData);
    return safeData;
  }

  const blocklist = stored.blocklist || [];
  const isBlocklisted = blocklist.some(d => hostname === d || hostname.endsWith('.' + d));
  if (isBlocklisted) {
    const blockData = {
      url: url,
      probability: 0.99,
      risk_score: 99,
      risk_level: 'phishing',
      prediction: 1,
      verdict: 'BLOCKED (Blocklist)',
      is_whitelisted: false,
      factors: [{ feature: 'custom_blocklist', impact: 'HIGH', direction: 'phishing', message: 'Domain in your custom blocklist' }],
      latency_ms: 0,
      timestamp: new Date().toISOString()
    };
    applyResult(tabId, url, blockData);
    return blockData;
  }

  setBadge(tabId, 'loading');

  try {
    const response = await fetch(API_BASE + '/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url }),
      signal: AbortSignal.timeout(12000),
    });

    if (!response.ok) throw new Error('HTTP ' + response.status);

    const raw = await response.json();
    const data = normalizeResponse(raw, url);

    urlCache.set(url, { ts: now, data: data });

    if (urlCache.size > 200) {
      let oldest = null;
      urlCache.forEach(function(v, k) {
        if (!oldest || v.ts < urlCache.get(oldest).ts) oldest = k;
      });
      if (oldest) urlCache.delete(oldest);
    }

    applyResult(tabId, url, data);
    return data;

  } catch (err) {
    console.error('[PhishGuard] API error:', err.message);
    setBadge(tabId, 'error');
    const errorData = { error: true, message: err.message, url: url };
    urlCache.set(url, { ts: now, data: errorData });
    return errorData;
  }
}

function applyResult(tabId, url, data) {
  if (data.error) { setBadge(tabId, 'error'); return; }
  const risk = data.risk_level;
  setBadge(tabId, risk);
  const obj = {};
  obj['tab_' + tabId] = { url: url, result: data, ts: Date.now() };
  chrome.storage.session.set(obj);

  // Save to persistent scan history
  saveToHistory(url, data);

  // Check bypass and settings before blocking
  const bypassKey = 'bypass_' + url;
  chrome.storage.session.get(bypassKey, function(bState) {
    if (bState && bState[bypassKey]) return; // User opted to proceed

    chrome.storage.local.get(['settings'], function(sData) {
      const s = sData.settings || {};
      const autoBlock = s.autoBlock !== false;
      const showBanners = s.banners !== false;
      const notifsEnabled = s.notifications !== false;
      const warnThreshold = s.threshold_warning || 0.50;
      const blockThreshold = s.threshold_block || 0.85;

      // 1. Phishing / High-Risk Interception
      if (autoBlock && (risk === 'phishing' || data.probability >= blockThreshold)) {
        const factorsParam = data.factors && data.factors.length ? '&reasons=' + encodeURIComponent(JSON.stringify(data.factors)) : '';
        const blockedUrl = chrome.runtime.getURL(
          'pages/blocked.html?url=' + encodeURIComponent(url) + '&prob=' + data.probability.toFixed(3) + factorsParam
        );
        chrome.tabs.update(tabId, { url: blockedUrl });

        // Show desktop notification
        if (notifsEnabled && chrome.notifications && chrome.notifications.create) {
          try {
            chrome.notifications.create({
              type: 'basic',
              iconUrl: 'icons/icon48.png',
              title: '🚨 PhishGuard Threat Blocked',
              message: 'Blocked high-risk phishing URL: ' + url.slice(0, 50),
              priority: 2
            });
          } catch(e) {}
        }
      }
      // 2. Suspicious / Warning Banner Injection
      else if (risk === 'warning' || (data.probability >= warnThreshold && data.probability < blockThreshold)) {
        if (showBanners) {
          try {
            chrome.tabs.sendMessage(tabId, { type: 'SHOW_BANNER', risk: 'warning', probability: data.probability });
          } catch(e) {}
        }
        if (notifsEnabled && chrome.notifications && chrome.notifications.create) {
          try {
            chrome.notifications.create({
              type: 'basic',
              iconUrl: 'icons/icon48.png',
              title: '⚠️ PhishGuard Warning',
              message: 'Caution: This site has a ' + Math.round(data.probability * 100) + '% phishing risk score.',
              priority: 1
            });
          } catch(e) {}
        }
      }
    });
  });
}

chrome.webNavigation.onCommitted.addListener(async function(details) {
  if (details.frameId !== 0) return;
  if (!details.url.startsWith('http')) return;
  const extOrigin = chrome.runtime.getURL('').slice(0, -1);
  if (details.url.startsWith(extOrigin)) return;
  const url = details.url.split('#')[0];
  await analyzeUrl(url, details.tabId);
}, { url: [{ schemes: ['http', 'https'] }] });

chrome.tabs.onRemoved.addListener(function(tabId) {
  chrome.storage.session.remove('tab_' + tabId);
});

chrome.runtime.onMessage.addListener(function(msg, sender, sendResponse) {
  if (msg.type === 'GET_RESULT') {
    chrome.tabs.query({ active: true, currentWindow: true }, async function(tabs) {
      if (!tabs[0]) { sendResponse({ error: 'No active tab' }); return; }
      const tabId = tabs[0].id;
      const url = tabs[0].url;
      const key = 'tab_' + tabId;
      chrome.storage.session.get(key, async function(stored) {
        if (stored[key] && stored[key].url === url) {
          sendResponse({ result: stored[key].result, cached: true });
        } else {
          const data = await analyzeUrl(url, tabId);
          sendResponse({ result: data, cached: false });
        }
      });
    });
    return true;
  }

  if (msg.type === 'REANALYZE') {
    chrome.tabs.query({ active: true, currentWindow: true }, async function(tabs) {
      if (!tabs[0]) { sendResponse({ error: 'No active tab' }); return; }
      urlCache.delete(tabs[0].url);
      chrome.storage.session.remove('tab_' + tabs[0].id);
      const data = await analyzeUrl(tabs[0].url, tabs[0].id);
      sendResponse({ result: data });
    });
    return true;
  }

  if (msg.type === 'FEEDBACK') {
    fetch(API_BASE + '/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(msg.payload),
    })
      .then(function(r) { return r.json(); })
      .then(function(d) { sendResponse({ ok: true, data: d }); })
      .catch(function(e) { sendResponse({ ok: false, error: e.message }); });
    return true;
  }

  if (msg.type === 'PROCEED_ANYWAY') {
    const obj = {};
    obj['bypass_' + msg.url] = true;
    chrome.storage.session.set(obj);
    sendResponse({ ok: true });
    return true;
  }
});


// ---- Save to scan history (local storage) ----
function saveToHistory(url, data) {
  if (data.error || data.is_whitelisted) return;
  chrome.storage.local.get('scanHistory', function(stored) {
    const history = stored.scanHistory || [];
    history.push({
      url: url,
      risk_level: data.risk_level,
      probability: data.probability,
      ts: Date.now(),
    });
    // Keep last 500 entries
    const trimmed = history.slice(-500);
    chrome.storage.local.set({ scanHistory: trimmed });
  });
}

chrome.runtime.onInstalled.addListener(function(details) {
  if (details.reason === 'install') {
    chrome.storage.local.set({
      settings: {
        autoBlock: true,
        notifications: true,
        threshold_warning: 0.5,
        threshold_block: 0.85,
      }
    });
  }
});