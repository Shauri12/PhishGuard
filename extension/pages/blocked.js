// PhishGuard - Blocked Page Logic
document.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(location.search);
  const url    = params.get('url')  || 'Unknown URL';
  const prob   = parseFloat(params.get('prob') || '0.95');
  const pct    = Math.round(prob * 100);

  const blockedUrlEl = document.getElementById('blocked-url');
  if (blockedUrlEl) blockedUrlEl.textContent = url;

  const confPctEl = document.getElementById('conf-pct');
  if (confPctEl) confPctEl.textContent = pct + '%';

  const riskScoreVal = document.getElementById('risk-score-val');
  if (riskScoreVal) riskScoreVal.textContent = pct + '%';

  // Animate risk bar
  requestAnimationFrame(() => {
    setTimeout(() => {
      const riskFill = document.getElementById('risk-fill');
      if (riskFill) riskFill.style.width = pct + '%';
    }, 300);
  });

  // Load dynamic reasons from URL params if available
  const reasonsParam = params.get('reasons');
  if (reasonsParam) {
    try {
      const reasons = JSON.parse(decodeURIComponent(reasonsParam));
      const list = document.getElementById('reasons-list');
      if (list) {
        list.innerHTML = '';
        const icons = { HIGH: '🔴', MEDIUM: '🟡', LOW: '🔵' };
        reasons.slice(0, 5).forEach(r => {
          const icon = icons[r.impact] || '⚠️';
          list.innerHTML += '<div class="reason-item">' +
            '<div class="reason-icon ' + (r.impact||'').toLowerCase() + '">' + icon + '</div>' +
            '<div class="reason-text">' +
              '<h4>' + (r.feature || '').replace(/_/g,' ') + '</h4>' +
              '<p>' + (r.message || '') + '</p>' +
            '</div>' +
            '<span class="impact-badge ' + (r.impact||'') + '">' + (r.impact||'') + '</span>' +
          '</div>';
        });
      }
    } catch(e) {}
  }

  const btnSafety = document.getElementById('btn-safety');
  if (btnSafety) {
    btnSafety.addEventListener('click', () => {
      if (history.length > 1) history.back();
      else window.close();
    });
  }

  const btnProceed = document.getElementById('btn-proceed-anyway');
  if (btnProceed) {
    btnProceed.addEventListener('click', () => {
      if (confirm('WARNING: This site is likely phishing. Are you absolutely sure you want to proceed?')) {
        chrome.runtime.sendMessage({ type: 'PROCEED_ANYWAY', url: url }, () => {
          window.location.href = url;
        });
      }
    });
  }

  const btnReport = document.getElementById('btn-report-fp');
  if (btnReport) {
    btnReport.addEventListener('click', () => {
      chrome.runtime.sendMessage({
        type: 'FEEDBACK',
        payload: { url: url, correct_label: 0, predicted_label: 1, probability: prob }
      }, resp => {
        alert('Thank you! Your feedback has been recorded and will help improve PhishGuard.');
      });
    });
  }

  const btnSettings = document.getElementById('btn-open-settings');
  if (btnSettings) {
    btnSettings.addEventListener('click', () => {
      if (chrome.runtime.openOptionsPage) {
        chrome.runtime.openOptionsPage();
      } else {
        window.open(chrome.runtime.getURL('pages/settings.html'));
      }
    });
  }
});
