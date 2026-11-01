// PhishGuard – Content Script
// Runs in the page context; collects page metadata and sends to background.

(function () {
  'use strict';

  // Avoid double-injection
  if (window.__phishguard_injected) return;
  window.__phishguard_injected = true;

  // ─── Collect page signals ──────────────────────────────────────────────────
  function collectPageData() {
    const title = document.title || '';
    const allLinks = document.querySelectorAll('a[href]');
    const domain = location.hostname.replace(/^www\./, '');

    let extLinks = 0;
    let intLinks = 0;
    let emptyLinks = 0;

    allLinks.forEach(a => {
      const href = a.getAttribute('href') || '';
      if (!href || href === '#' || href.startsWith('javascript:')) {
        emptyLinks++;
      } else {
        try {
          const u = new URL(href, location.href);
          if (u.hostname.replace(/^www\./, '') === domain) intLinks++;
          else extLinks++;
        } catch (_) { emptyLinks++; }
      }
    });

    const totalLinks = intLinks + extLinks + emptyLinks;
    const ratioInt = totalLinks > 0 ? intLinks / totalLinks : 0;

    return {
      title,
      nb_hyperlinks: totalLinks,
      ratio_intHyperlinks: ratioInt,
      empty_title: title.trim() === '' ? 1 : 0,
      domain_in_title: title.toLowerCase().includes(domain.toLowerCase()) ? 1 : 0,
      url: location.href,
    };
  }

  // ─── Send page data once DOM is ready ─────────────────────────────────────
  function sendPageData() {
    try {
      const data = collectPageData();
      chrome.runtime.sendMessage({ type: 'PAGE_DATA', payload: data });
    } catch (e) {
      // Extension may have been reloaded – ignore
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', sendPageData);
  } else {
    sendPageData();
  }

  // ─── Overlay banner injection (for warning level: medium) ─────────────────
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'SHOW_BANNER') {
      injectBanner(msg.risk, msg.probability);
    }
    if (msg.type === 'REMOVE_BANNER') {
      const existing = document.getElementById('phishguard-banner');
      if (existing) existing.remove();
    }
  });

  function injectBanner(risk, probability) {
    if (document.getElementById('phishguard-banner')) return;

    const pct = Math.round(probability * 100);
    const isWarning = risk === 'warning';

    const banner = document.createElement('div');
    banner.id = 'phishguard-banner';
    banner.style.cssText = `
      position: fixed;
      top: 0; left: 0; right: 0;
      z-index: 2147483647;
      background: ${isWarning ? 'linear-gradient(135deg,#92400e,#b45309)' : 'linear-gradient(135deg,#7f1d1d,#991b1b)'};
      color: #fff;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 14px;
      padding: 10px 20px;
      display: flex;
      align-items: center;
      gap: 12px;
      box-shadow: 0 2px 20px rgba(0,0,0,0.4);
      animation: phishguard-slide-in 0.3s ease;
    `;

    const styleEl = document.createElement('style');
    styleEl.textContent = `
      @keyframes phishguard-slide-in {
        from { transform: translateY(-100%); }
        to   { transform: translateY(0); }
      }
    `;
    document.head.appendChild(styleEl);

    banner.innerHTML = `
      <span style="font-size:20px">${isWarning ? '⚠️' : '🚫'}</span>
      <span style="flex:1">
        <strong>PhishGuard ${isWarning ? 'Warning' : 'Alert'}:</strong>
        This page has a ${pct}% phishing risk score.
        ${isWarning ? 'Proceed with caution.' : 'This site may be dangerous!'}
      </span>
      <button id="phishguard-dismiss" style="
        background:rgba(255,255,255,0.2);border:1px solid rgba(255,255,255,0.4);
        color:#fff;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:13px;
      ">Dismiss</button>
    `;

    document.body.prepend(banner);

    document.getElementById('phishguard-dismiss').addEventListener('click', () => {
      banner.remove();
    });
  }
})();
