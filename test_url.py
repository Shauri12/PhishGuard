"""
Root launcher for PhishGuard interactive tester.
Usage:
    python test_url.py "https://example.com"
"""
import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_SCRIPT = os.path.join(SCRIPT_DIR, "backend", "ml", "test_interactive.py")

if __name__ == "__main__":
    import subprocess
    cmd = [sys.executable, TARGET_SCRIPT] + sys.argv[1:]
    sys.exit(subprocess.call(cmd))
