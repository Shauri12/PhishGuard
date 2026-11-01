// PhishGuard - Warning Page Logic
document.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get('url') || 'Unknown URL';
  const prob = parseFloat(params.get('prob') || '0.9');

  const urlEl = document.getElementById('danger-url');
  if (urlEl) urlEl.textContent = targetUrl;

  const pct = Math.round(prob * 100);
  const pctEl = document.getElementById('prob-pct');
  if (pctEl) pctEl.textContent = pct + '%';

  requestAnimationFrame(() => {
    setTimeout(() => {
      const fillEl = document.getElementById('prob-fill');
      if (fillEl) fillEl.style.width = Math.min(pct, 100) + '%';
    }, 150);
  });

  const btnBack = document.getElementById('btn-back');
  if (btnBack) {
    btnBack.addEventListener('click', () => {
      if (history.length > 1) {
        history.back();
      } else {
        window.close();
      }
    });
  }

  const btnProceed = document.getElementById('btn-proceed');
  if (btnProceed) {
    btnProceed.addEventListener('click', () => {
      if (confirm('Are you sure you want to proceed to this suspicious site?')) {
        chrome.runtime.sendMessage({ type: 'PROCEED_ANYWAY', url: targetUrl }, () => {
          window.location.href = targetUrl;
        });
      }
    });
  }
});
