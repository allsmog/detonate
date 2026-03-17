"""Dashboard analytics routes providing aggregate statistics and timelines."""

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_db
from detonate.models.analysis import Analysis
from detonate.models.submission import Submission
from detonate.schemas.search import (
    AnalysisStatusBreakdown,
    DashboardStats,
    IOCEntry,
    TimelinePoint,
    TimelineResponse,
    TopIOCs,
    TypeCount,
)

logger = logging.getLogger("detonate.api.routes.dashboard")

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
) -> DashboardStats:
    """Return aggregate statistics for the dashboard.

    Includes submission/analysis totals, verdict breakdown, time-based counts,
    average score, top file types, top tags, and analysis status breakdown.
    """
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=today_start.weekday())
    month_start = today_start.replace(day=1)

    # -- Total counts --
    total_submissions_result = await db.execute(
        select(func.count(Submission.id))
    )
    total_submissions = total_submissions_result.scalar_one()

    total_analyses_result = await db.execute(
        select(func.count(Analysis.id))
    )
    total_analyses = total_analyses_result.scalar_one()

    # -- Verdict breakdown --
    verdict_rows = await db.execute(
        select(
            func.lower(Submission.verdict),
            func.count(Submission.id),
        ).group_by(func.lower(Submission.verdict))
    )
    verdict_map: dict[str, int] = {}
    for verdict_val, count in verdict_rows.all():
        verdict_map[verdict_val or "unknown"] = count

    verdicts = {
        "malicious": verdict_map.get("malicious", 0),
        "suspicious": verdict_map.get("suspicious", 0),
        "clean": verdict_map.get("clean", 0),
        "unknown": verdict_map.get("unknown", 0),
    }

    # -- Time-based submission counts --
    submissions_today_result = await db.execute(
        select(func.count(Submission.id)).where(
            Submission.submitted_at >= today_start
        )
    )
    submissions_today = submissions_today_result.scalar_one()

    submissions_week_result = await db.execute(
        select(func.count(Submission.id)).where(
            Submission.submitted_at >= week_start
        )
    )
    submissions_this_week = submissions_week_result.scalar_one()

    submissions_month_result = await db.execute(
        select(func.count(Submission.id)).where(
            Submission.submitted_at >= month_start
        )
    )
    submissions_this_month = submissions_month_result.scalar_one()

    # -- Average score --
    avg_score_result = await db.execute(
        select(func.avg(Submission.score))
    )
    avg_score_raw = avg_score_result.scalar_one()
    average_score = round(float(avg_score_raw), 1) if avg_score_raw is not None else 0.0

    # -- Top file types (top 10) --
    file_type_rows = await db.execute(
        select(
            Submission.file_type,
            func.count(Submission.id).label("cnt"),
        )
        .where(Submission.file_type.isnot(None))
        .group_by(Submission.file_type)
        .order_by(text("cnt DESC"))
        .limit(10)
    )
    top_file_types = [
        TypeCount(type=row[0] or "unknown", count=row[1])
        for row in file_type_rows.all()
    ]

    # -- Top tags (top 10) --
    # Unnest the tags array and count occurrences
    tag_rows = await db.execute(
        select(
            func.unnest(Submission.tags).label("tag"),
            func.count().label("cnt"),
        )
        .where(Submission.tags.isnot(None))
        .group_by(text("tag"))
        .order_by(text("cnt DESC"))
        .limit(10)
    )
    top_tags = [
        TypeCount(type=row[0], count=row[1])
        for row in tag_rows.all()
    ]

    # -- Analysis status breakdown --
    status_rows = await db.execute(
        select(
            func.lower(Analysis.status),
            func.count(Analysis.id),
        ).group_by(func.lower(Analysis.status))
    )
    status_map: dict[str, int] = {}
    for status_val, count in status_rows.all():
        status_map[status_val or "unknown"] = count

    analysis_status_breakdown = AnalysisStatusBreakdown(
        completed=status_map.get("completed", 0),
        failed=status_map.get("failed", 0),
        running=status_map.get("running", 0),
        queued=status_map.get("queued", 0),
    )

    return DashboardStats(
        total_submissions=total_submissions,
        total_analyses=total_analyses,
        verdicts=verdicts,
        submissions_today=submissions_today,
        submissions_this_week=submissions_this_week,
        submissions_this_month=submissions_this_month,
        average_score=average_score,
        top_file_types=top_file_types,
        top_tags=top_tags,
        analysis_status_breakdown=analysis_status_breakdown,
    )


@router.get("/dashboard/timeline", response_model=TimelineResponse)
async def get_submission_timeline(
    days: int = Query(default=30, ge=1, le=365, description="Number of days to look back"),
    granularity: str = Query(default="day", description="Granularity: 'day' or 'hour'"),
    db: AsyncSession = Depends(get_db),
) -> TimelineResponse:
    """Return submission timeline data for charting.

    Groups submissions by date (or hour) and includes verdict breakdown
    per time bucket.
    """
    if granularity not in ("day", "hour"):
        raise HTTPException(
            status_code=422,
            detail="Granularity must be 'day' or 'hour'.",
        )

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)

    if granularity == "day":
        # Truncate to date
        date_trunc = func.date_trunc("day", Submission.submitted_at)
    else:
        date_trunc = func.date_trunc("hour", Submission.submitted_at)

    # Total count per bucket
    rows = await db.execute(
        select(
            date_trunc.label("bucket"),
            func.count(Submission.id).label("total"),
            func.count(Submission.id).filter(
                func.lower(Submission.verdict) == "malicious"
            ).label("malicious"),
            func.count(Submission.id).filter(
                func.lower(Submission.verdict) == "suspicious"
            ).label("suspicious"),
            func.count(Submission.id).filter(
                func.lower(Submission.verdict) == "clean"
            ).label("clean"),
        )
        .where(Submission.submitted_at >= start)
        .group_by(text("bucket"))
        .order_by(text("bucket"))
    )

    points = []
    for row in rows.all():
        bucket_dt = row[0]
        if granularity == "day":
            date_str = bucket_dt.strftime("%Y-%m-%d") if bucket_dt else ""
        else:
            date_str = bucket_dt.isoformat() if bucket_dt else ""

        points.append(
            TimelinePoint(
                date=date_str,
                count=row[1],
                malicious=row[2],
                suspicious=row[3],
                clean=row[4],
            )
        )

    return TimelineResponse(
        points=points,
        days=days,
        granularity=granularity,
    )


@router.get("/dashboard/top-iocs", response_model=TopIOCs)
async def get_top_iocs(
    limit: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> TopIOCs:
    """Extract the most common IOCs (IPs and domains) from analysis results.

    Parses the JSONB result field of completed analyses to find network
    connections, DNS queries, and HTTP hosts.
    """
    # Fetch completed analyses with results
    result = await db.execute(
        select(Analysis.result)
        .where(Analysis.status == "completed")
        .where(Analysis.result.isnot(None))
        .order_by(Analysis.completed_at.desc())
        .limit(500)
    )
    analysis_results = result.scalars().all()

    ip_counts: dict[str, int] = {}
    domain_counts: dict[str, int] = {}

    for res_data in analysis_results:
        if not isinstance(res_data, dict):
            continue

        _extract_iocs_from_result(res_data, ip_counts, domain_counts)

    # Sort and limit
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:limit]

    return TopIOCs(
        ips=[IOCEntry(value=ip, count=count) for ip, count in top_ips],
        domains=[IOCEntry(value=domain, count=count) for domain, count in top_domains],
    )


def _extract_iocs_from_result(
    res_data: dict,
    ip_counts: dict[str, int],
    domain_counts: dict[str, int],
) -> None:
    """Extract IPs and domains from an analysis result JSONB object.

    Handles multiple result structures:
    - result.network.connections[].dst_ip
    - result.network.dns[].query / result.network.dns[].answers[].data
    - result.network.http_hosts[]
    - result.connections[].address (legacy)
    - result.dns_queries[].query (legacy)
    """
    # Standard network structure
    network = res_data.get("network", {})
    if isinstance(network, dict):
        # Connections
        connections = network.get("connections", [])
        if isinstance(connections, list):
            for conn in connections:
                if isinstance(conn, dict):
                    dst_ip = conn.get("dst_ip") or conn.get("address") or conn.get("ip")
                    if dst_ip and isinstance(dst_ip, str) and not _is_private_ip(dst_ip):
                        ip_counts[dst_ip] = ip_counts.get(dst_ip, 0) + 1

        # DNS queries
        dns_entries = network.get("dns", [])
        if isinstance(dns_entries, list):
            for entry in dns_entries:
                if isinstance(entry, dict):
                    query = entry.get("query") or entry.get("domain")
                    if query and isinstance(query, str):
                        domain_counts[query] = domain_counts.get(query, 0) + 1
                    # Also check answers for IPs
                    answers = entry.get("answers", [])
                    if isinstance(answers, list):
                        for answer in answers:
                            if isinstance(answer, dict):
                                data = answer.get("data") or answer.get("ip")
                                if data and isinstance(data, str) and _looks_like_ip(data):
                                    if not _is_private_ip(data):
                                        ip_counts[data] = ip_counts.get(data, 0) + 1

        # HTTP hosts
        http_hosts = network.get("http_hosts", [])
        if isinstance(http_hosts, list):
            for host in http_hosts:
                if isinstance(host, str):
                    if _looks_like_ip(host):
                        if not _is_private_ip(host):
                            ip_counts[host] = ip_counts.get(host, 0) + 1
                    else:
                        domain_counts[host] = domain_counts.get(host, 0) + 1

    # Legacy flat structure
    connections_flat = res_data.get("connections", [])
    if isinstance(connections_flat, list):
        for conn in connections_flat:
            if isinstance(conn, dict):
                addr = conn.get("address") or conn.get("dst_ip") or conn.get("ip")
                if addr and isinstance(addr, str) and not _is_private_ip(addr):
                    ip_counts[addr] = ip_counts.get(addr, 0) + 1

    dns_flat = res_data.get("dns_queries", [])
    if isinstance(dns_flat, list):
        for entry in dns_flat:
            if isinstance(entry, dict):
                query = entry.get("query") or entry.get("domain")
                if query and isinstance(query, str):
                    domain_counts[query] = domain_counts.get(query, 0) + 1


def _looks_like_ip(value: str) -> bool:
    """Quick check if a string looks like an IPv4 address."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _is_private_ip(ip: str) -> bool:
    """Check if an IPv4 address is in a private range."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False

    # 10.0.0.0/8
    if octets[0] == 10:
        return True
    # 172.16.0.0/12
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    # 192.168.0.0/16
    if octets[0] == 192 and octets[1] == 168:
        return True
    # 127.0.0.0/8
    if octets[0] == 127:
        return True
    return False
