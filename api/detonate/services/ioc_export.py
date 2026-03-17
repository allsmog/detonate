import csv
import io
import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.models.analysis import Analysis
from detonate.models.submission import Submission


async def extract_iocs(db: AsyncSession, submission: Submission) -> dict:
    """Extract all IOCs from a submission and its completed analyses."""
    iocs: dict = {
        "hashes": {
            "sha256": submission.file_hash_sha256,
            "md5": getattr(submission, "file_hash_md5", None),
            "sha1": getattr(submission, "file_hash_sha1", None),
        },
        "ips": [],
        "domains": [],
        "urls": [],
        "emails": [],
        "file_paths": [],
        "registry_keys": [],
        "mutexes": [],
    }

    if submission.url:
        iocs["urls"].append({"value": submission.url, "source": "submission"})

    # Get all completed analyses for this submission
    result = await db.execute(
        select(Analysis).where(
            Analysis.submission_id == submission.id,
            Analysis.status == "completed",
        )
    )

    seen_ips: set[str] = set()
    seen_domains: set[str] = set()
    seen_urls: set[str] = {submission.url or ""}

    for analysis in result.scalars():
        r = analysis.result or {}

        # Network connections from strace
        for conn in r.get("network", []):
            addr = conn.get("address", "")
            if addr and addr not in ("127.0.0.1", "::1", "0.0.0.0") and addr not in seen_ips:
                iocs["ips"].append({
                    "value": addr,
                    "port": conn.get("port"),
                    "source": "strace",
                })
                seen_ips.add(addr)

        # PCAP data
        pcap = r.get("pcap", {})

        for dns in pcap.get("dns_queries", []):
            domain = dns.get("query", "")
            if domain and domain not in seen_domains:
                iocs["domains"].append({
                    "value": domain,
                    "type": dns.get("type", "A"),
                    "source": "pcap",
                })
                seen_domains.add(domain)
            resp = dns.get("response", "")
            if resp and resp not in seen_ips:
                iocs["ips"].append({"value": resp, "source": "dns_response"})
                seen_ips.add(resp)

        for host in pcap.get("http_hosts", []):
            if host and host not in seen_domains:
                iocs["domains"].append({"value": host, "source": "http_host"})
                seen_domains.add(host)

        for conn in pcap.get("connections", []):
            dst = conn.get("dst_ip", "")
            if dst and dst not in ("127.0.0.1", "::1", "0.0.0.0") and dst not in seen_ips:
                iocs["ips"].append({
                    "value": dst,
                    "port": conn.get("dst_port"),
                    "source": "pcap",
                })
                seen_ips.add(dst)

        # File paths from dropped/created files
        for f in r.get("files_created", []):
            path = f.get("path", "")
            if path:
                iocs["file_paths"].append({
                    "value": path,
                    "size": f.get("size"),
                })

        # Processes that may reveal more IOCs
        for proc in r.get("processes", []):
            cmdline = proc.get("cmdline", "")
            # Extract URLs from command lines
            if "http://" in cmdline or "https://" in cmdline:
                for token in cmdline.split():
                    if token.startswith(("http://", "https://")) and token not in seen_urls:
                        iocs["urls"].append({"value": token, "source": "cmdline"})
                        seen_urls.add(token)

        # Suricata alerts (if present)
        for alert in r.get("suricata_alerts", []):
            src = alert.get("src_ip", "")
            dst = alert.get("dst_ip", "")
            if src and src not in seen_ips and src not in ("127.0.0.1", "::1", "0.0.0.0"):
                iocs["ips"].append({"value": src, "source": "suricata_alert"})
                seen_ips.add(src)
            if dst and dst not in seen_ips and dst not in ("127.0.0.1", "::1", "0.0.0.0"):
                iocs["ips"].append({"value": dst, "source": "suricata_alert"})
                seen_ips.add(dst)

    return iocs


def export_csv(iocs: dict) -> str:
    """Export IOCs as CSV."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["type", "value", "context"])

    # Hashes
    for hash_type, hash_val in iocs["hashes"].items():
        if hash_val:
            writer.writerow(["hash", hash_val, hash_type])

    for ip in iocs["ips"]:
        ctx = ip.get("source", "")
        if ip.get("port"):
            ctx += f" port={ip['port']}"
        writer.writerow(["ip", ip["value"], ctx.strip()])

    for domain in iocs["domains"]:
        writer.writerow(["domain", domain["value"], domain.get("source", "")])

    for url in iocs["urls"]:
        writer.writerow(["url", url["value"], url.get("source", "")])

    for path in iocs["file_paths"]:
        ctx = f"size={path['size']}" if path.get("size") is not None else ""
        writer.writerow(["file_path", path["value"], ctx])

    for reg in iocs["registry_keys"]:
        writer.writerow(["registry_key", reg["value"], reg.get("source", "")])

    for mutex in iocs["mutexes"]:
        writer.writerow(["mutex", mutex["value"], mutex.get("source", "")])

    return output.getvalue()


def export_stix(iocs: dict, submission_id: str) -> dict:
    """Export IOCs as STIX 2.1 bundle."""
    objects: list[dict] = []
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Hash indicators
    for hash_type, hash_val in iocs["hashes"].items():
        if hash_val:
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "name": f"File hash ({hash_type})",
                "description": f"File hash from Detonate submission {submission_id}",
                "pattern": f"[file:hashes.'{hash_type.upper()}' = '{hash_val}']",
                "pattern_type": "stix",
                "valid_from": now,
                "labels": ["malicious-activity"],
            })

    # IP indicators
    for ip in iocs["ips"]:
        pattern_type = "ipv6" if ":" in ip["value"] else "ipv4"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": f"IP Address: {ip['value']}",
            "description": f"Network indicator from {ip.get('source', 'analysis')}",
            "pattern": f"[{pattern_type}-addr:value = '{ip['value']}']",
            "pattern_type": "stix",
            "valid_from": now,
            "labels": ["malicious-activity"],
        })

    # Domain indicators
    for domain in iocs["domains"]:
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": f"Domain: {domain['value']}",
            "description": f"Domain from {domain.get('source', 'analysis')}",
            "pattern": f"[domain-name:value = '{domain['value']}']",
            "pattern_type": "stix",
            "valid_from": now,
            "labels": ["malicious-activity"],
        })

    # URL indicators
    for url in iocs["urls"]:
        # Escape single quotes in URL for STIX pattern
        escaped = url["value"].replace("'", "\\'")
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": f"URL: {url['value'][:80]}",
            "description": f"URL from {url.get('source', 'analysis')}",
            "pattern": f"[url:value = '{escaped}']",
            "pattern_type": "stix",
            "valid_from": now,
            "labels": ["malicious-activity"],
        })

    # File path indicators
    for fp in iocs["file_paths"]:
        escaped = fp["value"].replace("\\", "\\\\").replace("'", "\\'")
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": f"File: {fp['value'][:80]}",
            "pattern": f"[file:name = '{escaped}']",
            "pattern_type": "stix",
            "valid_from": now,
            "labels": ["malicious-activity"],
        })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def export_json(iocs: dict) -> str:
    """Export IOCs as formatted JSON."""
    return json.dumps(iocs, indent=2, default=str)
