"""
Tests for HTML report export (core/report_export.py) — fully offline, no deps.
Covers the Markdown→HTML conversion, the security escaping, and the wiring into
ReportingAgent._save_report(format="html").
"""

from pathlib import Path

from agents.reporting_agent import ReportingAgent
from config.settings import settings
from core.report_export import markdown_to_html, render_html

# ── markdown_to_html ────────────────────────────────────────────────────────────

def test_headings_bold_italic_code():
    out = markdown_to_html("# Title\n\nsome **bold** and *italic* and `code` here")
    assert "<h1>Title</h1>" in out
    assert "<strong>bold</strong>" in out
    assert "<em>italic</em>" in out
    assert "<code>code</code>" in out


def test_unordered_and_ordered_lists():
    assert "<ul>" in markdown_to_html("- a\n- b")
    assert "<ol>" in markdown_to_html("1. first\n2. second")


def test_table_rendering():
    md = "| Sev | Count |\n| --- | --- |\n| High | 3 |"
    out = markdown_to_html(md)
    assert "<table>" in out and "<th>Sev</th>" in out and "<td>High</td>" in out


def test_code_fence_block():
    out = markdown_to_html("```\nnmap -sV 10.0.0.5\n```")
    assert "<pre><code>" in out and "nmap -sV 10.0.0.5" in out


def test_allowed_link_rendered_disallowed_inert():
    assert '<a href="https://x.io">x</a>' in markdown_to_html("[x](https://x.io)")
    js = markdown_to_html("[x](javascript:alert(1))")
    assert "<a" not in js and "javascript:alert(1)" in js   # inert, not a link


# ── security: untrusted finding text must be escaped ────────────────────────────

def test_html_is_escaped_no_xss():
    out = markdown_to_html("Banner: <script>alert('xss')</script> <img onerror=x>")
    assert "<script>" not in out
    assert "&lt;script&gt;" in out
    assert "onerror=x" not in out or "&lt;img" in out


def test_render_html_is_self_contained_document():
    out = render_html("Pentest Report", "## Summary\n\nAll clear.",
                      meta={"Engagement": "ENG-1"}, risk={"rating": "High", "score": 7.2})
    assert out.startswith("<!doctype html>")
    assert "<title>Pentest Report</title>" in out
    assert "<h2>Summary</h2>" in out
    assert "ENG-1" in out
    assert "rpt-badge high" in out and "High" in out
    assert "http://" not in out and "https://" not in out   # no external assets


def test_render_html_escapes_title():
    out = render_html("<script>x</script>", "body")
    assert "<title>&lt;script&gt;x&lt;/script&gt;</title>" in out


# ── wiring into the reporting agent ─────────────────────────────────────────────

def test_save_report_html_writes_rendered_file():
    agent = ReportingAgent()
    result = agent._save_report("Q3 Assessment", "# Findings\n\n- one\n- two", format="html")
    path = Path(result["saved"])
    assert path.suffix == ".html"
    text = path.read_text(encoding="utf-8")
    assert text.startswith("<!doctype html>")
    assert "<h1>Q3 Assessment</h1>" in text and "<li>one</li>" in text


def test_save_report_markdown_unchanged():
    agent = ReportingAgent()
    result = agent._save_report("Plain", "# raw markdown", format="markdown")
    path = Path(result["saved"])
    assert path.suffix == ".md"
    assert path.read_text(encoding="utf-8") == "# raw markdown"   # not transformed


def test_reports_dir_is_isolated_tmp():
    # conftest points reports_dir at a temp dir — guard against writing real data
    assert "rtagent_test_" in str(settings.reports_dir)
