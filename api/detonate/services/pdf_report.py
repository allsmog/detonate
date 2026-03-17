"""HTML report generation for submission threat reports.

Builds a self-contained HTML document suitable for browser viewing or
print-to-PDF.  Uses only the Python standard library -- no weasyprint,
reportlab, or other third-party rendering dependencies.
"""

import html
import logging
import re
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.models.analysis import Analysis
from detonate.models.submission import Submission

logger = logging.getLogger("detonate.services.pdf_report")


# ---------------------------------------------------------------------------
# Markdown -> HTML (stdlib only)
# ---------------------------------------------------------------------------

def markdown_to_html(md: str) -> str:
    """Convert a subset of Markdown to HTML without external dependencies.

    Handles: headings, fenced code blocks, tables, unordered lists,
    horizontal rules, bold, and inline code.
    """
    lines = md.split("\n")
    html_lines: list[str] = []
    in_code_block = False
    in_table = False
    in_list = False

    for line in lines:
        # --- Fenced code blocks ---
        if line.strip().startswith("```"):
            if in_code_block:
                html_lines.append("</pre></code>")
                in_code_block = False
            else:
                html_lines.append("<code><pre>")
                in_code_block = True
            continue

        if in_code_block:
            html_lines.append(html.escape(line))
            continue

        # --- Headings ---
        if line.startswith("### "):
            html_lines.append(f"<h3>{html.escape(line[4:])}</h3>")
            continue
        if line.startswith("## "):
            html_lines.append(f"<h2>{html.escape(line[3:])}</h2>")
            continue
        if line.startswith("# "):
            html_lines.append(f"<h1>{html.escape(line[2:])}</h1>")
            continue

        # --- Tables ---
        if "|" in line and line.strip().startswith("|"):
            cells = [c.strip() for c in line.split("|")[1:-1]]
            # Skip separator rows (e.g. |---|---|)
            if all(set(c) <= {"-", ":", " "} for c in cells):
                continue
            if not in_table:
                html_lines.append(
                    "<table border='1' cellpadding='4' cellspacing='0' "
                    "style='border-collapse:collapse;width:100%'>"
                )
                in_table = True
            row = "".join(
                f"<td>{html.escape(c)}</td>" for c in cells
            )
            html_lines.append(f"<tr>{row}</tr>")
            continue

        # Close table if we've left a table block
        if in_table:
            html_lines.append("</table>")
            in_table = False

        # --- Unordered lists ---
        stripped = line.strip()
        if stripped.startswith("- "):
            if not in_list:
                html_lines.append("<ul>")
                in_list = True
            html_lines.append(f"<li>{html.escape(stripped[2:])}</li>")
            continue

        # Close list if we've left a list block
        if in_list:
            html_lines.append("</ul>")
            in_list = False

        # --- Horizontal rule ---
        if stripped == "---":
            html_lines.append("<hr>")
            continue

        # --- Paragraph with inline formatting ---
        if stripped:
            escaped = html.escape(line)
            escaped = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)
            escaped = re.sub(r"`(.+?)`", r"<code>\1</code>", escaped)
            html_lines.append(f"<p>{escaped}</p>")

    # Close any still-open blocks
    if in_table:
        html_lines.append("</table>")
    if in_list:
        html_lines.append("</ul>")
    if in_code_block:
        html_lines.append("</pre></code>")

    return "\n".join(html_lines)


# ---------------------------------------------------------------------------
# HTML report builder
# ---------------------------------------------------------------------------

_REPORT_CSS = """\
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    max-width: 900px;
    margin: 0 auto;
    padding: 20px;
    color: #1a1a1a;
    font-size: 14px;
    line-height: 1.5;
}
h1 { color: #dc2626; border-bottom: 2px solid #dc2626; padding-bottom: 8px; }
h2 { color: #333; margin-top: 28px; border-bottom: 1px solid #e5e7eb; padding-bottom: 4px; }
h3 { color: #555; }
table { border-collapse: collapse; width: 100%; margin: 12px 0; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 13px; }
th { background: #f5f5f5; font-weight: 600; }
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
}
.malicious { background: #fee2e2; color: #dc2626; }
.suspicious { background: #fef3c7; color: #d97706; }
.clean { background: #d1fae5; color: #059669; }
.unknown { background: #f3f4f6; color: #6b7280; }
code { background: #f5f5f5; padding: 2px 4px; border-radius: 3px; font-size: 13px; }
pre { background: #f5f5f5; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; }
.meta { color: #666; font-size: 13px; }
.hash { font-family: monospace; font-size: 13px; word-break: break-all; }
.section-empty { color: #999; font-style: italic; font-size: 13px; }
@media print {
    body { max-width: 100%; padding: 0; }
    table { page-break-inside: avoid; }
}
"""


def _esc(value: str | None, fallback: str = "N/A") -> str:
    """HTML-escape a nullable string with a fallback."""
    return html.escape(value) if value else fallback


def _verdict_class(verdict: str) -> str:
    if verdict in ("malicious", "suspicious", "clean", "unknown"):
        return verdict
    return "unknown"


def build_html_report(
    submission: Submission,
    analysis: Analysis | None,
    ai_report: str | None,
) -> str:
    """Build a self-contained HTML report for a submission.

    Args:
        submission: The submission model instance.
        analysis: The latest completed analysis (may be ``None``).
        ai_report: AI-generated markdown report text (may be ``None``).

    Returns:
        A complete HTML document as a string.
    """
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    verdict_cls = _verdict_class(submission.verdict)

    parts: list[str] = []

    # --- Document head ---
    parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Detonate Report - {_esc(submission.filename, 'Unknown')}</title>
<style>
{_REPORT_CSS}
</style>
</head>
<body>
<h1>Detonate Threat Report</h1>
<p class="meta">Generated: {now}</p>
""")

    # --- File information ---
    parts.append("""<h2>File Information</h2>
<table>""")
    parts.append(f"<tr><th>Filename</th><td>{_esc(submission.filename)}</td></tr>")
    parts.append(
        f'<tr><th>SHA256</th><td class="hash">{submission.file_hash_sha256}</td></tr>'
    )
    parts.append(
        f'<tr><th>MD5</th><td class="hash">{_esc(submission.file_hash_md5)}</td></tr>'
    )
    parts.append(
        f'<tr><th>SHA1</th><td class="hash">{_esc(submission.file_hash_sha1)}</td></tr>'
    )
    parts.append(
        f"<tr><th>File Size</th><td>{submission.file_size or 0:,} bytes</td></tr>"
    )
    parts.append(f"<tr><th>File Type</th><td>{_esc(submission.file_type)}</td></tr>")
    parts.append(f"<tr><th>MIME Type</th><td>{_esc(submission.mime_type)}</td></tr>")
    parts.append(
        f'<tr><th>Verdict</th><td><span class="badge {verdict_cls}">'
        f"{submission.verdict}</span></td></tr>"
    )
    parts.append(f"<tr><th>Score</th><td>{submission.score}/100</td></tr>")

    if submission.tags:
        tags_html = ", ".join(html.escape(t) for t in submission.tags)
        parts.append(f"<tr><th>Tags</th><td>{tags_html}</td></tr>")

    parts.append("</table>")

    # --- Analysis results ---
    if analysis and analysis.result:
        result: dict = analysis.result

        # Process activity
        procs = result.get("processes", [])
        if procs:
            parts.append("<h2>Process Activity</h2><table>")
            parts.append(
                "<tr><th>PID</th><th>PPID</th><th>Command</th><th>Arguments</th></tr>"
            )
            for p in procs[:30]:
                args = " ".join(p.get("args", []))
                parts.append(
                    f"<tr><td>{p.get('pid', '-')}</td>"
                    f"<td>{p.get('ppid', '-')}</td>"
                    f"<td><code>{_esc(p.get('command', ''))}</code></td>"
                    f"<td>{_esc(args[:120])}</td></tr>"
                )
            if len(procs) > 30:
                parts.append(
                    f"<tr><td colspan='4' class='section-empty'>"
                    f"... and {len(procs) - 30} more processes</td></tr>"
                )
            parts.append("</table>")

        # Network connections
        net = result.get("network", [])
        if net:
            parts.append("<h2>Network Connections</h2><table>")
            parts.append("<tr><th>Protocol</th><th>Address</th><th>Port</th></tr>")
            for n in net[:30]:
                parts.append(
                    f"<tr><td>{_esc(str(n.get('protocol', '')))}</td>"
                    f"<td><code>{_esc(n.get('address', ''))}</code></td>"
                    f"<td>{n.get('port', '-')}</td></tr>"
                )
            if len(net) > 30:
                parts.append(
                    f"<tr><td colspan='3' class='section-empty'>"
                    f"... and {len(net) - 30} more connections</td></tr>"
                )
            parts.append("</table>")

        # DNS queries
        pcap = result.get("pcap", {})
        dns = pcap.get("dns_queries", [])
        if dns:
            parts.append("<h2>DNS Queries</h2><table>")
            parts.append("<tr><th>Domain</th><th>Type</th><th>Response</th></tr>")
            for d in dns[:30]:
                parts.append(
                    f"<tr><td><code>{_esc(d.get('query', ''))}</code></td>"
                    f"<td>{_esc(d.get('type', ''))}</td>"
                    f"<td>{_esc(d.get('response', '-'))}</td></tr>"
                )
            if len(dns) > 30:
                parts.append(
                    f"<tr><td colspan='3' class='section-empty'>"
                    f"... and {len(dns) - 30} more queries</td></tr>"
                )
            parts.append("</table>")

        # HTTP hosts
        http_hosts = pcap.get("http_hosts", [])
        if http_hosts:
            parts.append("<h2>HTTP Hosts</h2><ul>")
            for h in http_hosts[:20]:
                parts.append(f"<li><code>{_esc(h)}</code></li>")
            parts.append("</ul>")

        # Files created
        files = result.get("files_created", [])
        if files:
            parts.append("<h2>Files Created</h2><table>")
            parts.append("<tr><th>Path</th><th>Size</th></tr>")
            for f in files[:30]:
                parts.append(
                    f"<tr><td><code>{_esc(f.get('path', ''))}</code></td>"
                    f"<td>{f.get('size', 0):,} bytes</td></tr>"
                )
            if len(files) > 30:
                parts.append(
                    f"<tr><td colspan='2' class='section-empty'>"
                    f"... and {len(files) - 30} more files</td></tr>"
                )
            parts.append("</table>")

        # Files modified
        files_mod = result.get("files_modified", [])
        if files_mod:
            parts.append("<h2>Files Modified</h2><table>")
            parts.append("<tr><th>Path</th><th>Size</th></tr>")
            for f in files_mod[:20]:
                parts.append(
                    f"<tr><td><code>{_esc(f.get('path', ''))}</code></td>"
                    f"<td>{f.get('size', 0):,} bytes</td></tr>"
                )
            parts.append("</table>")

        # Files deleted
        files_del = result.get("files_deleted", [])
        if files_del:
            parts.append("<h2>Files Deleted</h2><ul>")
            for f in files_del[:20]:
                parts.append(f"<li><code>{_esc(f.get('path', ''))}</code></li>")
            parts.append("</ul>")

        # IDS alerts (Suricata)
        ids_alerts = result.get("ids_alerts", [])
        if ids_alerts:
            parts.append("<h2>IDS Alerts</h2><table>")
            parts.append(
                "<tr><th>Severity</th><th>Signature</th>"
                "<th>Category</th><th>Source</th><th>Destination</th></tr>"
            )
            for a in ids_alerts[:20]:
                sev = {1: "High", 2: "Medium"}.get(a.get("severity"), "Low")
                sev_color = {
                    "High": "#dc2626",
                    "Medium": "#d97706",
                    "Low": "#ca8a04",
                }.get(sev, "#666")
                parts.append(
                    f"<tr><td style='color:{sev_color};font-weight:600'>{sev}</td>"
                    f"<td>{_esc(a.get('signature', ''))}</td>"
                    f"<td>{_esc(a.get('category', ''))}</td>"
                    f"<td><code>{a.get('src_ip', '?')}:{a.get('src_port', '?')}</code></td>"
                    f"<td><code>{a.get('dst_ip', '?')}:{a.get('dst_port', '?')}</code></td></tr>"
                )
            if len(ids_alerts) > 20:
                parts.append(
                    f"<tr><td colspan='5' class='section-empty'>"
                    f"... and {len(ids_alerts) - 20} more alerts</td></tr>"
                )
            parts.append("</table>")

        # YARA matches
        yara = result.get("yara", {})
        sample_matches = yara.get("sample_matches", [])
        dropped_matches = yara.get("dropped_file_matches", [])
        if sample_matches or dropped_matches:
            parts.append("<h2>YARA Matches</h2>")
            if sample_matches:
                parts.append("<h3>Sample Matches</h3><table>")
                parts.append(
                    "<tr><th>Rule</th><th>Tags</th><th>Description</th></tr>"
                )
                for m in sample_matches:
                    tags = ", ".join(m.get("tags", []))
                    desc = (m.get("meta") or {}).get("description", "-")
                    parts.append(
                        f"<tr><td><code>{_esc(m.get('rule', ''))}</code></td>"
                        f"<td>{_esc(tags)}</td>"
                        f"<td>{_esc(desc)}</td></tr>"
                    )
                parts.append("</table>")
            if dropped_matches:
                parts.append("<h3>Dropped File Matches</h3>")
                for df in dropped_matches:
                    parts.append(
                        f"<p><code>{_esc(df.get('file', ''))}</code></p><table>"
                    )
                    parts.append(
                        "<tr><th>Rule</th><th>Tags</th><th>Description</th></tr>"
                    )
                    for m in df.get("matches", []):
                        tags = ", ".join(m.get("tags", []))
                        desc = (m.get("meta") or {}).get("description", "-")
                        parts.append(
                            f"<tr><td><code>{_esc(m.get('rule', ''))}</code></td>"
                            f"<td>{_esc(tags)}</td>"
                            f"<td>{_esc(desc)}</td></tr>"
                        )
                    parts.append("</table>")

        # MITRE ATT&CK techniques
        mitre: list[dict] = (
            result.get("mitre_techniques")
            or getattr(analysis, "mitre_techniques", None)
            or []
        )
        if mitre:
            parts.append("<h2>MITRE ATT&CK Techniques</h2><table>")
            parts.append(
                "<tr><th>Technique</th><th>Name</th><th>Confidence</th></tr>"
            )
            for t in mitre[:20]:
                parts.append(
                    f"<tr><td><code>{_esc(t.get('technique_id', ''))}</code></td>"
                    f"<td>{_esc(t.get('name', ''))}</td>"
                    f"<td>{t.get('confidence', 'N/A')}</td></tr>"
                )
            parts.append("</table>")
    else:
        parts.append(
            '<p class="section-empty">No dynamic analysis results available.</p>'
        )

    # --- AI analysis ---
    if ai_report:
        parts.append("<h2>AI Analysis</h2>")
        parts.append(markdown_to_html(ai_report))

    # --- IOC summary ---
    parts.append(_build_ioc_section(submission, analysis))

    # --- Footer ---
    parts.append("""
<hr>
<p class="meta">
    Report generated by <strong>Detonate</strong> &mdash;
    Open Source Malware Analysis Sandbox
</p>
</body>
</html>""")

    return "".join(parts)


def _build_ioc_section(
    submission: Submission,
    analysis: Analysis | None,
) -> str:
    """Build a consolidated Indicators of Compromise section."""
    iocs: list[str] = []

    # Hash IOCs
    iocs.append("<h2>Indicators of Compromise</h2>")
    iocs.append("<h3>File Hashes</h3><table>")
    iocs.append(
        f'<tr><th>SHA256</th><td class="hash">{submission.file_hash_sha256}</td></tr>'
    )
    if submission.file_hash_md5:
        iocs.append(
            f'<tr><th>MD5</th><td class="hash">{submission.file_hash_md5}</td></tr>'
        )
    if submission.file_hash_sha1:
        iocs.append(
            f'<tr><th>SHA1</th><td class="hash">{submission.file_hash_sha1}</td></tr>'
        )
    iocs.append("</table>")

    if analysis and analysis.result:
        result = analysis.result

        # Network IOCs
        net = result.get("network", [])
        pcap = result.get("pcap", {})
        dns = pcap.get("dns_queries", [])
        http_hosts = pcap.get("http_hosts", [])

        addresses: set[str] = set()
        domains: set[str] = set()

        for n in net:
            addr = n.get("address", "")
            if addr:
                addresses.add(addr)
        for d in dns:
            query = d.get("query", "")
            if query:
                domains.add(query)
        for h in http_hosts:
            if h:
                domains.add(h)

        if addresses:
            iocs.append("<h3>Network Addresses</h3><ul>")
            for addr in sorted(addresses):
                iocs.append(f"<li><code>{_esc(addr)}</code></li>")
            iocs.append("</ul>")

        if domains:
            iocs.append("<h3>Domains</h3><ul>")
            for domain in sorted(domains):
                iocs.append(f"<li><code>{_esc(domain)}</code></li>")
            iocs.append("</ul>")

        # Dropped file IOCs
        files_created = result.get("files_created", [])
        if files_created:
            iocs.append("<h3>Dropped Files</h3><ul>")
            for f in files_created[:20]:
                iocs.append(f"<li><code>{_esc(f.get('path', ''))}</code></li>")
            iocs.append("</ul>")

    return "".join(iocs)


def build_csv_iocs(
    submission: Submission,
    analysis: Analysis | None,
) -> str:
    """Build a CSV string of IOCs extracted from submission and analysis.

    Returns a comma-separated string with columns: type, value, context.
    """
    rows: list[str] = ["type,value,context"]

    # File hashes
    rows.append(f"sha256,{submission.file_hash_sha256},{_csv_safe(submission.filename)}")
    if submission.file_hash_md5:
        rows.append(
            f"md5,{submission.file_hash_md5},{_csv_safe(submission.filename)}"
        )
    if submission.file_hash_sha1:
        rows.append(
            f"sha1,{submission.file_hash_sha1},{_csv_safe(submission.filename)}"
        )

    if analysis and analysis.result:
        result = analysis.result

        # Network addresses
        for n in result.get("network", []):
            addr = n.get("address", "")
            port = n.get("port", "")
            proto = n.get("protocol", "")
            if addr:
                rows.append(f"ip,{_csv_safe(addr)},{proto}:{port}")

        # DNS domains
        pcap = result.get("pcap", {})
        seen_domains: set[str] = set()
        for d in pcap.get("dns_queries", []):
            query = d.get("query", "")
            if query and query not in seen_domains:
                seen_domains.add(query)
                rows.append(f"domain,{_csv_safe(query)},dns-query")

        for h in pcap.get("http_hosts", []):
            if h and h not in seen_domains:
                seen_domains.add(h)
                rows.append(f"domain,{_csv_safe(h)},http-host")

        # Dropped files
        for f in result.get("files_created", []):
            path = f.get("path", "")
            if path:
                rows.append(f"file,{_csv_safe(path)},dropped")

    return "\n".join(rows)


def _csv_safe(value: str | None) -> str:
    """Escape a value for safe CSV inclusion."""
    if not value:
        return ""
    # Wrap in quotes if it contains commas, quotes, or newlines
    if "," in value or '"' in value or "\n" in value:
        return '"' + value.replace('"', '""') + '"'
    return value


async def get_latest_analysis(
    db: AsyncSession,
    submission_id,
) -> Analysis | None:
    """Fetch the most recent completed analysis for a submission."""
    result = await db.execute(
        select(Analysis)
        .where(
            Analysis.submission_id == submission_id,
            Analysis.status == "completed",
        )
        .order_by(Analysis.completed_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()
