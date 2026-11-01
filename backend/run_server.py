"""
Launcher for the PhishGuard FastAPI server.
Usage:
  python run_server.py
"""
import sys
import os
import uvicorn

# Add backend directory to sys.path so 'app' imports resolve cleanly
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

if __name__ == "__main__":
    print("[+] Starting PhishGuard Server on http://127.0.0.1:8000 ...")
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True, reload_dirs=[CURRENT_DIR], log_level="info")
