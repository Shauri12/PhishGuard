# PhishGuard Chrome Extension – Phase 3

> Real-time AI-powered phishing URL detection with SHAP explainability, built as a Chrome Extension (Manifest V3).

---

## 📁 Folder Structure

```
extension/
├── manifest.json          # Manifest V3 config
├── background.js          # Service worker – navigation events, API calls, badge
├── content.js             # Content script – page metadata collection & banners
├── icons/                 # Extension icons (16/32/48/128 px)
│   ├── icon16.png
│   ├── icon32.png
│   ├── icon48.png
│   └── icon128.png
├── popup/
│   ├── popup.html         # Glassmorphism popup UI
│   ├── popup.css          # Premium dark theme styles
│   └── popup.js           # Popup logic – results, SHAP, feedback, settings
└── pages/
    ├── warning.html       # Full-screen phishing warning intercept page
    └── safe.html          # Safe page indicator
```

---

## 🚀 How to Load in Chrome

1. **Start the backend server first:**
   ```powershell
   cd phishing-detector\backend
   python run_server.py
   # Server runs at http://127.0.0.1:8000
   ```

2. **Load the extension:**
   - Open Chrome → `chrome://extensions/`
   - Enable **Developer Mode** (top-right toggle)
   - Click **"Load unpacked"**
   - Select the `phishing-detector\extension\` folder
   - PhishGuard appears in your toolbar ✓

3. **Usage:**
   - Visit any website – the badge auto-updates:
     - 🟢 `✓` = Safe
     - 🟡 `!` = Warning (moderate risk)
     - 🔴 `✗` = Phishing detected
     - 🟣 `…` = Analyzing
   - Click the extension icon to see the full popup with risk gauge, SHAP explanation, and feedback form
   - High-risk sites (≥85%) are **intercepted** and redirected to the warning page

---

## 🔧 Architecture

```
Browser Navigation
       │
       ▼
background.js (Service Worker)
  ├── webNavigation.onCommitted listener
  ├── POST http://127.0.0.1:8000/api/v1/predict
  ├── Badge update (safe/warning/phishing)
  ├── Session cache (5-minute TTL, 200 URL LRU)
  └── High-risk → redirect to pages/warning.html
       │
       ▼
content.js (per-tab)
  ├── Collects: page title, link counts, internal ratio
  └── Injects warning banner for medium-risk pages
       │
       ▼
popup.js (user click)
  ├── Queries background for cached result
  ├── Animated SVG risk gauge (0–100%)
  ├── SHAP factor bar chart (top 8 features)
  ├── Feedback reporting (POST /feedback)
  └── Settings persistence (chrome.storage.local)
```

---

## ⚙️ Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Auto-block | ✅ On | Redirect high-risk URLs to warning page |
| Notifications | ✅ On | Desktop notification on phishing detection |
| Warning threshold | 50% | Probability at which badge turns yellow |
| Block threshold | 85% | Probability at which page is intercepted |

---

## 🎨 UI Features

- **Glassmorphism popup** – 360px wide, dark theme, blur effects
- **Animated SVG gauge** – smooth probability arc animation
- **SHAP waterfall bars** – animated green/red contribution bars
- **Accordion sections** – collapsible "Why this result?" and "Feedback"
- **Settings overlay** – toggle switches, range sliders
- **In-page banner** – injected warning strip for medium-risk sites
- **Full-screen intercept** – animated warning card for high-risk sites

---

*PhishGuard Phase 3 – Chrome Extension | Built with Manifest V3*
