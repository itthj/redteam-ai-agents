"""
tests/conftest.py
──────────────────
Pytest bootstrap. Sets a safe, isolated test environment BEFORE any
project module (which imports config.settings) is loaded.
"""

import os
import sys
import tempfile
from pathlib import Path

# Make the project root importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Isolated data dirs so tests never touch real engagement data
_TMP = Path(tempfile.mkdtemp(prefix="rtagent_test_"))

# Force-set so the suite is hermetic — ambient env vars cannot change results
os.environ["ANTHROPIC_API_KEY"] = "sk-ant-test-not-a-real-key"
os.environ["AUTHORIZED_TARGETS"] = "192.168.56.0/24,10.0.0.5,*.lab.internal"
os.environ["ENGAGEMENT_ID"] = "ENG-TEST-001"
os.environ["ENGAGEMENT_NAME"] = "Pytest Engagement"
os.environ["OPERATOR_NAME"] = "pytest"
os.environ.pop("ENGAGEMENT_EXPIRY", None)
os.environ.pop("MCP_ENABLED_SERVERS", None)
os.environ["EVIDENCE_DIR"] = str(_TMP / "evidence")
os.environ["REPORTS_DIR"] = str(_TMP / "reports")
os.environ["KNOWLEDGE_DIR"] = str(_TMP / "knowledge")
