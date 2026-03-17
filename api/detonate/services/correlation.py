"""IOC correlation and similar submission discovery.

Extracts indicators of compromise (IOCs) from a submission's analysis
results and finds other submissions that share those indicators.  The
similarity score is based on the fraction of shared IOCs.
"""

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.models.analysis import Analysis
from detonate.models.submission import Submission
from detonate.services.llm import BaseLLMProvider

logger = logging.getLogger("detonate.services.correlation")

# Private / loopback addresses that should never be treated as IOCs.
_IGNORE_IPS = frozenset({"127.0.0.1", "::1", "0.0.0.0", "", "localhost"})


async def find_similar_submissions(
    db: AsyncSession,
    submission: Submission,
    llm: BaseLLMProvider | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Find submissions that share IOCs with the given submission.

    Checks for:
      1. Identical file hash (exact SHA-256 match, score = 1.0).
      2. Shared network IOCs (IP addresses and domains extracted from
         analysis network data and PCAP results).
      3. Shared YARA rule matches.

    Args:
        db: Async database session.
        submission: The reference submission.
        llm: Optional LLM provider (reserved for future behavioural ranking).
        limit: Maximum number of similar submissions to return.

    Returns:
        A list of dicts, each containing ``id``, ``filename``,
        ``similarity_score``, ``shared_iocs``, and ``verdict``.
    """
    results: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    # -- 1. Get latest completed analysis for this submission --
    analysis_q = await db.execute(
        select(Analysis)
        .where(
            Analysis.submission_id == submission.id,
            Analysis.status == "completed",
        )
        .order_by(Analysis.completed_at.desc())
        .limit(1)
    )
    latest = analysis_q.scalar_one_or_none()

    our_iocs = _extract_iocs(latest)
    our_yara = _extract_yara_rules(latest)

    # -- 2. Exact hash matches (deduplication) --
    hash_q = await db.execute(
        select(Submission).where(
            Submission.file_hash_sha256 == submission.file_hash_sha256,
            Submission.id != submission.id,
        )
        .limit(limit)
    )
    for s in hash_q.scalars():
        sid = str(s.id)
        if sid in seen_ids:
            continue
        seen_ids.add(sid)
        results.append({
            "id": sid,
            "filename": s.filename,
            "similarity_score": 1.0,
            "shared_iocs": [f"SHA256:{s.file_hash_sha256}"],
            "verdict": s.verdict,
            "submitted_at": s.submitted_at.isoformat() if s.submitted_at else None,
        })

    if len(results) >= limit:
        return results[:limit]

    # -- 3. Network IOC + YARA overlap with other submissions --
    has_network_iocs = bool(our_iocs["ips"] or our_iocs["domains"])
    has_yara = bool(our_yara)

    if has_network_iocs or has_yara:
        # Fetch recent completed analyses from *other* submissions.
        # We cap at 200 to keep the query bounded.
        other_analyses_q = await db.execute(
            select(Analysis)
            .where(
                Analysis.status == "completed",
                Analysis.submission_id != submission.id,
            )
            .order_by(Analysis.completed_at.desc())
            .limit(200)
        )

        # Group by submission_id so we only process the newest analysis per sub.
        per_submission: dict[str, Analysis] = {}
        for analysis in other_analyses_q.scalars():
            sub_key = str(analysis.submission_id)
            if sub_key not in per_submission:
                per_submission[sub_key] = analysis

        for sub_id_str, analysis in per_submission.items():
            if sub_id_str in seen_ids:
                continue

            shared: list[str] = []

            # Compare network IOCs
            if has_network_iocs:
                other_iocs = _extract_iocs(analysis)
                for ip in our_iocs["ips"]:
                    if ip in other_iocs["ips"]:
                        shared.append(f"IP:{ip}")
                for domain in our_iocs["domains"]:
                    if domain in other_iocs["domains"]:
                        shared.append(f"Domain:{domain}")

            # Compare YARA rules
            if has_yara:
                other_yara = _extract_yara_rules(analysis)
                for rule in our_yara:
                    if rule in other_yara:
                        shared.append(f"YARA:{rule}")

            if not shared:
                continue

            # Fetch the actual submission record for metadata.
            sub_q = await db.execute(
                select(Submission).where(Submission.id == analysis.submission_id)
            )
            sub = sub_q.scalar_one_or_none()
            if sub is None:
                continue

            total_our_iocs = (
                len(our_iocs["ips"])
                + len(our_iocs["domains"])
                + len(our_yara)
            )
            score = min(len(shared) / max(total_our_iocs, 1), 1.0)

            seen_ids.add(sub_id_str)
            results.append({
                "id": sub_id_str,
                "filename": sub.filename,
                "similarity_score": round(score, 2),
                "shared_iocs": shared,
                "verdict": sub.verdict,
                "submitted_at": sub.submitted_at.isoformat() if sub.submitted_at else None,
            })

            if len(results) >= limit:
                break

    # Sort descending by similarity score, then by filename for stability.
    results.sort(key=lambda r: (-r["similarity_score"], r.get("filename") or ""))
    return results[:limit]


def _extract_iocs(analysis: Analysis | None) -> dict[str, set[str]]:
    """Extract network IOCs from an analysis result.

    Returns a dict with ``ips`` and ``domains`` sets.
    """
    iocs: dict[str, set[str]] = {"ips": set(), "domains": set()}

    if not analysis or not analysis.result:
        return iocs

    result: dict = analysis.result

    # Direct network connections
    for conn in result.get("network", []):
        addr = conn.get("address", "")
        if addr and addr not in _IGNORE_IPS:
            iocs["ips"].add(addr)

    # PCAP data
    pcap = result.get("pcap", {})
    if pcap:
        for dns in pcap.get("dns_queries", []):
            query = dns.get("query", "").strip()
            if query:
                iocs["domains"].add(query)
            resp = dns.get("response", "").strip()
            if resp and resp not in _IGNORE_IPS:
                iocs["ips"].add(resp)

        for host in pcap.get("http_hosts", []):
            host = host.strip() if isinstance(host, str) else ""
            if host:
                iocs["domains"].add(host)

        for conn in pcap.get("connections", []):
            dst = conn.get("dst", "").strip() if isinstance(conn.get("dst"), str) else ""
            if dst and dst not in _IGNORE_IPS:
                iocs["ips"].add(dst)

    return iocs


def _extract_yara_rules(analysis: Analysis | None) -> set[str]:
    """Extract the set of matched YARA rule names from an analysis result."""
    rules: set[str] = set()
    if not analysis or not analysis.result:
        return rules

    for match in analysis.result.get("yara_matches", []):
        rule = match.get("rule", "")
        if rule:
            rules.add(rule)

    return rules
