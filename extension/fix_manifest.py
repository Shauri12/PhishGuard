import json

csp = "script-src 'self'; object-src 'self'"

manifest = {
  "manifest_version": 3,
  "name": "PhishGuard - AI Phishing Detector",
  "short_name": "PhishGuard",
  "version": "1.0.0",
  "description": "Real-time AI-powered phishing URL detection with SHAP explainability.",
  "icons": {"16":"icons/icon16.png","32":"icons/icon32.png","48":"icons/icon48.png","128":"icons/icon128.png"},
  "action": {
    "default_popup": "popup/popup.html",
    "default_icon": {"16":"icons/icon16.png","32":"icons/icon32.png","48":"icons/icon48.png","128":"icons/icon128.png"},
    "default_title": "PhishGuard - Check this page"
  },
  "background": {"service_worker": "background.js", "type": "module"},
  "content_scripts": [{"matches": ["<all_urls>"], "js": ["content.js"], "run_at": "document_idle", "all_frames": False}],
  "permissions": ["activeTab","storage","webNavigation","tabs","scripting","notifications"],
  "host_permissions": ["http://127.0.0.1:8000/*","http://localhost:8000/*","<all_urls>"],
  "web_accessible_resources": [{"resources": ["pages/warning.html","pages/safe.html","icons/*.png","popup/popup.html"], "matches": ["<all_urls>"]}],
  "content_security_policy": {"extension_pages": csp}
}

with open("manifest.json", "w", encoding="ascii") as f:
    json.dump(manifest, f, indent=2, ensure_ascii=True)

with open("manifest.json") as f:
    json.load(f)
print("manifest.json OK")
