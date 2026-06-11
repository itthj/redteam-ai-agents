"""
core/report_export.py
──────────────────────
Render an engagement report (a Markdown narrative) into a single, self-contained,
print-friendly HTML file — no external assets, no network. For a PDF, open it and
use the browser's *Print → Save as PDF* (the stylesheet has print rules); that
avoids a heavy native PDF dependency (weasyprint/cairo).

Pure stdlib — no new dependency. **Security:** a report aggregates finding text
that originated from untrusted targets (banners, page content). All of it is
HTML-escaped before rendering and link schemes are allow-listed, so opening a
report can never execute attacker-controlled content in the viewer.
"""

from __future__ import annotations

import html
import re
import time

_ALLOWED_LINK = re.compile(r"^(?:https?://|/|#|mailto:)", re.IGNORECASE)
_SENTINEL = "\x00"


def _link_sub(m: re.Match) -> str:
    label, url = m.group(1), m.group(2)
    if _ALLOWED_LINK.match(html.unescape(url)):
        return f'<a href="{url}">{label}</a>'
    return f"{label} ({url})"   # render a disallowed scheme as inert text


def _inline(text: str) -> str:
    """Apply inline Markdown to already-escaped text (code spans are protected)."""
    spans: list[str] = []

    def _stash(m: re.Match) -> str:
        spans.append(f"<code>{m.group(1)}</code>")
        return f"{_SENTINEL}{len(spans) - 1}{_SENTINEL}"

    text = re.sub(r"`([^`]+)`", _stash, text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", _link_sub, text)
    text = re.sub(rf"{_SENTINEL}(\d+){_SENTINEL}", lambda m: spans[int(m.group(1))], text)
    return text


def markdown_to_html(md: str) -> str:
    """Minimal, safe Markdown→HTML for machine-generated reports. Escapes first."""
    if not md:
        return ""
    lines = html.escape(md).split("\n")
    out: list[str] = []
    n = len(lines)
    i = 0
    in_code = False
    code_buf: list[str] = []
    open_list: str | None = None

    def close_list() -> None:
        nonlocal open_list
        if open_list:
            out.append(f"</{open_list}>")
            open_list = None

    while i < n:
        line = lines[i]
        stripped = line.strip()

        if stripped.startswith("```"):
            if in_code:
                out.append("<pre><code>" + "\n".join(code_buf) + "</code></pre>")
                code_buf, in_code = [], False
            else:
                close_list()
                in_code = True
            i += 1
            continue
        if in_code:
            code_buf.append(line)
            i += 1
            continue

        # table — header row followed by a |---|---| separator
        if ("|" in stripped and i + 1 < n and "-" in lines[i + 1]
                and re.match(r"^\s*\|?[\s:|-]+\|?\s*$", lines[i + 1])):
            close_list()
            cells = lambda row: [c.strip() for c in row.strip().strip("|").split("|")]  # noqa: E731
            out.append("<table><thead><tr>"
                       + "".join(f"<th>{_inline(c)}</th>" for c in cells(stripped))
                       + "</tr></thead><tbody>")
            i += 2
            while i < n and "|" in lines[i].strip():
                out.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells(lines[i].strip())) + "</tr>")
                i += 1
            out.append("</tbody></table>")
            continue

        m = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if m:
            close_list()
            level = len(m.group(1))
            out.append(f"<h{level}>{_inline(m.group(2))}</h{level}>")
            i += 1
            continue

        if re.match(r"^(-{3,}|\*{3,}|_{3,})$", stripped):
            close_list()
            out.append("<hr>")
            i += 1
            continue

        if stripped.startswith("&gt;"):   # '>' was escaped
            close_list()
            out.append(f"<blockquote>{_inline(stripped[4:].strip())}</blockquote>")
            i += 1
            continue

        m = re.match(r"^[-*]\s+(.*)$", stripped)
        if m:
            if open_list != "ul":
                close_list()
                out.append("<ul>")
                open_list = "ul"
            out.append(f"<li>{_inline(m.group(1))}</li>")
            i += 1
            continue

        m = re.match(r"^\d+\.\s+(.*)$", stripped)
        if m:
            if open_list != "ol":
                close_list()
                out.append("<ol>")
                open_list = "ol"
            out.append(f"<li>{_inline(m.group(1))}</li>")
            i += 1
            continue

        if not stripped:
            close_list()
            i += 1
            continue

        close_list()
        out.append(f"<p>{_inline(stripped)}</p>")
        i += 1

    if in_code:
        out.append("<pre><code>" + "\n".join(code_buf) + "</code></pre>")
    close_list()
    return "\n".join(out)


_CSS = """
:root { --crit:#b00020; --high:#d35400; --med:#b8860b; --low:#2e7d32; --ink:#1a1a1a; --muted:#666; }
* { box-sizing: border-box; }
body { font: 15px/1.6 -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
       color: var(--ink); max-width: 920px; margin: 0 auto; padding: 2rem; }
.rpt-header { border-bottom: 3px solid var(--ink); padding-bottom: 1rem; margin-bottom: 2rem; }
.rpt-header h1 { margin: 0 0 .25rem; font-size: 1.8rem; }
.rpt-meta { color: var(--muted); font-size: .9rem; }
.rpt-badge { display: inline-block; margin-top: .6rem; padding: .25rem .7rem; border-radius: 4px;
             color: #fff; font-weight: 600; font-size: .85rem; background: var(--muted); }
.rpt-badge.critical { background: var(--crit); } .rpt-badge.high { background: var(--high); }
.rpt-badge.medium { background: var(--med); } .rpt-badge.low { background: var(--low); }
h2 { margin-top: 2rem; border-bottom: 1px solid #ddd; padding-bottom: .3rem; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: .92rem; }
th, td { border: 1px solid #ccc; padding: .45rem .6rem; text-align: left; vertical-align: top; }
th { background: #f4f4f4; }
code { background: #f0f0f0; padding: .1rem .35rem; border-radius: 3px; font-size: .9em; }
pre { background: #1e1e1e; color: #eee; padding: 1rem; border-radius: 6px; overflow-x: auto; }
pre code { background: none; color: inherit; padding: 0; }
blockquote { border-left: 4px solid #ccc; margin: 1rem 0; padding: .2rem 1rem; color: var(--muted); }
.rpt-footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #ddd;
              color: var(--muted); font-size: .8rem; }
@media print { body { max-width: none; padding: 0; } pre { white-space: pre-wrap; } a { color: inherit; } }
"""


def render_html(title: str, content_md: str, *, meta: dict | None = None,
                risk: dict | None = None) -> str:
    """Render a Markdown report into a standalone HTML document string."""
    safe_title = html.escape(title or "Engagement Report")
    meta_html = " · ".join(
        f"<strong>{html.escape(str(k))}:</strong> {html.escape(str(v))}"
        for k, v in (meta or {}).items()
    )
    badge = ""
    if risk and risk.get("rating"):
        rating = str(risk["rating"])
        score = risk.get("score")
        label = f"Risk: {html.escape(rating)}" + (f" ({score})" if score is not None else "")
        badge = f'<div class="rpt-badge {rating.lower()}">{label}</div>'
    body = markdown_to_html(content_md)
    generated = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{safe_title}</title>\n<style>{_CSS}</style></head>\n<body>\n"
        f'<header class="rpt-header"><h1>{safe_title}</h1>\n'
        f'<div class="rpt-meta">{meta_html}</div>{badge}</header>\n'
        f'<main class="rpt-body">\n{body}\n</main>\n'
        f'<footer class="rpt-footer">Generated {generated} · '
        "Authorized engagement use only · Secrets redacted in-report.</footer>\n"
        "</body></html>"
    )
