#!/usr/bin/env python
"""
scripts/dashboard.py — start the live dashboard and open it in your browser.

One command, no PATH / working-directory / host fuss:

    python scripts/dashboard.py

It binds to 127.0.0.1 (NOT 0.0.0.0 — that address is not browsable), opens
http://localhost:8000/dashboard automatically, and stays running until you press
CTRL+C. On Windows you can also just double-click run_dashboard.bat.
"""

import os
import sys
import threading
import webbrowser

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)

# Safe fallbacks so the server imports even without a populated .env (a real .env,
# if present, takes precedence — setdefault never overrides it).
os.environ.setdefault("ANTHROPIC_API_KEY", "sk-ant-dashboard-local")
os.environ.setdefault("AUTHORIZED_TARGETS", "10.0.0.0/24")

HOST = "127.0.0.1"
PORT = int(os.environ.get("API_PORT", "8000"))
URL = f"http://localhost:{PORT}/dashboard"


def main() -> None:
    try:
        import uvicorn
    except ImportError:
        sys.exit("uvicorn is not installed in this interpreter — use the project venv.")
    print(f"\n  Dashboard:  {URL}")
    print("  Opening your browser… leave this window open. Press CTRL+C to stop.\n")
    threading.Timer(2.0, lambda: webbrowser.open(URL)).start()
    uvicorn.run("api.server:app", host=HOST, port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
