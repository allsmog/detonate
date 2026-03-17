"""AI-powered threat report generation.

Gathers all available data for a submission (metadata, analysis results,
MITRE techniques, threat intel, IDS alerts) and uses an LLM to produce
a comprehensive Markdown threat report.
"""

import json
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.models.analysis import Analysis
from detonate.models.submission import Submission
from detonate.services.llm import BaseLLMProvider, LLMMessage

logger = logging.getLogger("detonate.services.report")

# Hard cap so the context string never blows past reasonable LLM context windows.
_MAX_CONTEXT_CHARS = 8000

REPORT_SYSTEM_PROMPT = """You are a senior malware analyst writing a comprehensive threat report.
Generate a detailed, professional report in Markdown format with the following sections:

## Executive Summary
Brief overview of the threat, risk level, and key findings.

## Static Analysis
File metadata, hashes, file type information.

## Dynamic Analysis
### Process Activity
Process tree with notable behaviors.
### Network Activity
Connections, DNS queries, HTTP hosts, C2 indicators.
### File System Activity
Created, modified, deleted files.

## MITRE ATT&CK Coverage
Techniques observed mapped to ATT&CK framework.

## Threat Intelligence
External intelligence from VirusTotal, AbuseIPDB, OTX if available.

## Indicators of Compromise (IOCs)
### Network IOCs
- IP addresses
- Domains
- URLs
### File IOCs
- Hashes (MD5, SHA1, SHA256)
- Dropped files

## Risk Assessment
Overall risk score and classification with justification.

Be thorough, technical, and actionable. Use tables where appropriate.
If a section has no data, note that no data was available."""


async def generate_report(
    db: AsyncSession,
    llm: BaseLLMProvider,
    submission: Submission,
    format: str = "markdown",
) -> str:
    """Generate a comprehensive AI threat report for a submission.

    Gathers all available data (submission metadata, analysis results,
    MITRE techniques, threat intel) and sends to LLM for report generation.

    Args:
        db: Async database session.
        llm: Configured LLM provider instance.
        submission: The submission to report on.
        format: Output format (currently only "markdown" is supported).

    Returns:
        A Markdown-formatted report string.

    Raises:
        RuntimeError: If the LLM call fails after retries.
    """
    # Load all completed analyses for this submission, newest first.
    analyses_q = await db.execute(
        select(Analysis)
        .where(
            Analysis.submission_id == submission.id,
            Analysis.status == "completed",
        )
        .order_by(Analysis.completed_at.desc())
    )
    analyses: list[Analysis] = list(analyses_q.scalars().all())
    latest: Analysis | None = analyses[0] if analyses else None

    context = _build_report_context(submission, analyses, latest)

    messages = [
        LLMMessage(
            role="user",
            content=(
                "Generate a comprehensive threat analysis report for the "
                "following submission:\n\n" + context
            ),
        )
    ]

    try:
        response = await llm.complete(messages, system=REPORT_SYSTEM_PROMPT)
    except Exception:
        logger.exception(
            "LLM report generation failed for submission %s", submission.id
        )
        raise RuntimeError(
            "Failed to generate report. The LLM provider returned an error."
        )

    return response.content


def _build_report_context(
    submission: Submission,
    analyses: list[Analysis],
    latest: Analysis | None,
) -> str:
    """Build a comprehensive context string from all available data.

    Truncates the final output to ``_MAX_CONTEXT_CHARS`` so that the LLM
    prompt stays within a reasonable size.
    """
    sections: list[str] = []

    # -- File metadata --
    meta_lines = [
        f"- Filename: {submission.filename or 'N/A'}",
        f"- SHA256: {submission.file_hash_sha256}",
        f"- MD5: {submission.file_hash_md5 or 'N/A'}",
        f"- SHA1: {submission.file_hash_sha1 or 'N/A'}",
        f"- Size: {submission.file_size or 0} bytes",
        f"- Type: {submission.file_type or 'N/A'}",
        f"- MIME: {submission.mime_type or 'N/A'}",
    ]
    if submission.tags:
        meta_lines.append(f"- Tags: {', '.join(submission.tags)}")
    if submission.verdict and submission.verdict != "unknown":
        meta_lines.append(f"- Current verdict: {submission.verdict} (score: {submission.score})")
    sections.append("## File Information\n" + "\n".join(meta_lines))

    # -- Cached AI summary --
    if submission.ai_summary:
        sections.append(f"## AI Summary\n{submission.ai_summary}")

    if submission.ai_verdict:
        sections.append(
            f"## AI Classification\n- Verdict: {submission.ai_verdict}"
            + (f" (score: {submission.ai_score}/100)" if submission.ai_score is not None else "")
        )

    # -- Analysis results (from the latest completed analysis) --
    if latest and latest.result:
        result: dict = latest.result

        # Process activity
        processes = result.get("processes", [])
        if processes:
            proc_lines = []
            for p in processes[:20]:
                args = " ".join(p.get("args", []))
                cmd = p.get("command", "?")
                proc_lines.append(
                    f"  - PID {p.get('pid', '?')} "
                    f"(ppid={p.get('ppid', '?')}): {cmd} {args}"
                )
            header = f"## Processes ({len(processes)} total)"
            if len(processes) > 20:
                header += " [truncated to 20]"
            sections.append(header + "\n" + "\n".join(proc_lines))

        # Network connections
        network = result.get("network", [])
        if network:
            net_lines = [
                f"  - {n.get('protocol', '?')} -> "
                f"{n.get('address', '?')}:{n.get('port', '?')}"
                for n in network[:20]
            ]
            header = f"## Network ({len(network)} connections)"
            if len(network) > 20:
                header += " [truncated to 20]"
            sections.append(header + "\n" + "\n".join(net_lines))

        # File system activity
        files_created = result.get("files_created", [])
        files_modified = result.get("files_modified", [])
        files_deleted = result.get("files_deleted", [])
        all_files = files_created + files_modified + files_deleted
        if all_files:
            file_lines = [
                f"  - {f.get('path', '?')} ({f.get('size', 0)} bytes)"
                for f in all_files[:20]
            ]
            header = f"## File Activity ({len(all_files)} files)"
            if len(all_files) > 20:
                header += " [truncated to 20]"
            sections.append(header + "\n" + "\n".join(file_lines))

        # PCAP / DNS
        pcap = result.get("pcap", {})
        if pcap:
            dns_queries = pcap.get("dns_queries", [])
            if dns_queries:
                dns_lines = [
                    f"  - {d.get('query', '?')} ({d.get('type', '?')})"
                    for d in dns_queries[:15]
                ]
                sections.append(
                    f"## DNS Queries ({len(dns_queries)} total)\n"
                    + "\n".join(dns_lines)
                )

            http_hosts = pcap.get("http_hosts", [])
            if http_hosts:
                sections.append(
                    "## HTTP Hosts\n"
                    + "\n".join(f"  - {h}" for h in http_hosts[:15])
                )

            connections = pcap.get("connections", [])
            if connections:
                conn_lines = [
                    f"  - {c.get('src', '?')} -> {c.get('dst', '?')} "
                    f"({c.get('protocol', '?')})"
                    for c in connections[:15]
                ]
                sections.append(
                    f"## PCAP Connections ({len(connections)} total)\n"
                    + "\n".join(conn_lines)
                )

        # IDS alerts (Suricata)
        ids_alerts = result.get("ids_alerts", [])
        if ids_alerts:
            alert_lines = [
                f"  - [{a.get('severity', '?')}] {a.get('signature', '?')} "
                f"(src={a.get('src_ip', '?')}:{a.get('src_port', '?')} -> "
                f"dst={a.get('dst_ip', '?')}:{a.get('dst_port', '?')})"
                for a in ids_alerts[:10]
            ]
            sections.append(
                f"## IDS Alerts ({len(ids_alerts)} total)\n"
                + "\n".join(alert_lines)
            )

        # YARA matches
        yara_matches = result.get("yara_matches", [])
        if yara_matches:
            yara_lines = [
                f"  - {y.get('rule', '?')} (tags: {', '.join(y.get('tags', []))})"
                for y in yara_matches[:10]
            ]
            sections.append(
                f"## YARA Matches ({len(yara_matches)} total)\n"
                + "\n".join(yara_lines)
            )

        # MITRE ATT&CK techniques
        mitre: list[dict] = (
            result.get("mitre_techniques")
            or getattr(latest, "mitre_techniques", None)
            or []
        )
        if mitre:
            mitre_lines = [
                f"  - {t.get('technique_id', '?')}: {t.get('name', '?')} "
                f"(confidence: {t.get('confidence', 'N/A')})"
                for t in mitre[:15]
            ]
            sections.append(
                f"## MITRE ATT&CK ({len(mitre)} techniques)\n"
                + "\n".join(mitre_lines)
            )

    # -- Threat intel (if stored on submission or latest analysis) --
    threat_intel = getattr(submission, "threat_intel", None)
    if not threat_intel and latest and latest.result:
        threat_intel = latest.result.get("threat_intel")
    if threat_intel:
        try:
            intel_str = json.dumps(threat_intel, indent=2)[:2000]
        except (TypeError, ValueError):
            intel_str = str(threat_intel)[:2000]
        sections.append(f"## Threat Intelligence\n{intel_str}")

    # -- Analysis count summary --
    if len(analyses) > 1:
        sections.append(
            f"## Analysis History\n"
            f"Total completed analyses: {len(analyses)}"
        )

    full_context = "\n\n".join(sections)
    if len(full_context) > _MAX_CONTEXT_CHARS:
        full_context = full_context[:_MAX_CONTEXT_CHARS] + "\n\n[Context truncated]"
    return full_context
