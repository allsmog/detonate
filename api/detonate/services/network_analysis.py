"""Advanced network analysis service.

Enriches PCAP / network results with service mapping, IP classification,
JA3 fingerprinting, DNS analysis, and suspicious-indicator detection.
"""

import hashlib
import ipaddress
import logging
import re
import struct
from typing import Any

logger = logging.getLogger("detonate.services.network_analysis")

# ---------------------------------------------------------------------------
# Private IP ranges
# ---------------------------------------------------------------------------

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_private_ip(ip: str) -> bool:
    """Return True when *ip* belongs to a well-known private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# JA3 fingerprinting
# ---------------------------------------------------------------------------

def compute_ja3_fingerprint(client_hello: bytes) -> str | None:
    """Compute JA3 fingerprint from a TLS ClientHello message.

    JA3 = md5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)

    GREASE values (RFC 8701) are filtered out so that the fingerprint is
    stable across TLS stacks that inject them.
    """
    try:
        if len(client_hello) < 44:
            return None

        # TLS record layer ------------------------------------------------
        content_type = client_hello[0]
        if content_type != 0x16:  # Handshake
            return None

        tls_version = struct.unpack(">H", client_hello[1:3])[0]  # noqa: F841

        # Handshake header ------------------------------------------------
        hs_type = client_hello[5]
        if hs_type != 0x01:  # ClientHello
            return None

        # Client version
        client_version = struct.unpack(">H", client_hello[9:11])[0]

        # Skip random (32 bytes) then session ID
        offset = 11 + 32
        if offset >= len(client_hello):
            return None
        session_id_len = client_hello[offset]
        offset += 1 + session_id_len

        # Cipher suites ---------------------------------------------------
        if offset + 2 > len(client_hello):
            return None
        cipher_len = struct.unpack(">H", client_hello[offset : offset + 2])[0]
        offset += 2
        ciphers: list[str] = []
        for i in range(0, cipher_len, 2):
            if offset + i + 2 > len(client_hello):
                break
            cipher = struct.unpack(">H", client_hello[offset + i : offset + i + 2])[0]
            # Skip GREASE values
            if (cipher & 0x0F0F) != 0x0A0A:
                ciphers.append(str(cipher))
        offset += cipher_len

        # Compression methods ---------------------------------------------
        if offset >= len(client_hello):
            return None
        comp_len = client_hello[offset]
        offset += 1 + comp_len

        # Extensions -------------------------------------------------------
        extensions: list[str] = []
        elliptic_curves: list[str] = []
        ec_point_formats: list[str] = []

        if offset + 2 <= len(client_hello):
            ext_len = struct.unpack(">H", client_hello[offset : offset + 2])[0]
            offset += 2
            ext_end = offset + ext_len

            while offset + 4 <= ext_end and offset + 4 <= len(client_hello):
                ext_type = struct.unpack(">H", client_hello[offset : offset + 2])[0]
                ext_data_len = struct.unpack(
                    ">H", client_hello[offset + 2 : offset + 4]
                )[0]

                # Skip GREASE
                if (ext_type & 0x0F0F) != 0x0A0A:
                    extensions.append(str(ext_type))

                ext_data_start = offset + 4

                # Supported Groups (elliptic curves) -- ext type 0x000a
                if ext_type == 0x000A and ext_data_len > 2:
                    if ext_data_start + 2 <= len(client_hello):
                        groups_len = struct.unpack(
                            ">H",
                            client_hello[ext_data_start : ext_data_start + 2],
                        )[0]
                        for i in range(0, groups_len, 2):
                            pos = ext_data_start + 2 + i
                            if pos + 2 > len(client_hello):
                                break
                            group = struct.unpack(
                                ">H", client_hello[pos : pos + 2]
                            )[0]
                            if (group & 0x0F0F) != 0x0A0A:
                                elliptic_curves.append(str(group))

                # EC point formats -- ext type 0x000b
                if ext_type == 0x000B and ext_data_len > 1:
                    if ext_data_start + 1 <= len(client_hello):
                        fmt_len = client_hello[ext_data_start]
                        for i in range(fmt_len):
                            pos = ext_data_start + 1 + i
                            if pos >= len(client_hello):
                                break
                            ec_point_formats.append(str(client_hello[pos]))

                offset += 4 + ext_data_len

        ja3_string = ",".join(
            [
                str(client_version),
                "-".join(ciphers),
                "-".join(extensions),
                "-".join(elliptic_curves),
                "-".join(ec_point_formats),
            ]
        )

        return hashlib.md5(ja3_string.encode()).hexdigest()
    except Exception:
        logger.debug("JA3 computation failed", exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Well-known port -> service mapping
# ---------------------------------------------------------------------------

PORT_SERVICES: dict[int, str] = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-TLS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    4443: "Pharos",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    6667: "IRC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9090: "WebLogic",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# Ports that are commonly used by C2 frameworks but not by legitimate services
_SUSPICIOUS_PORTS = {
    4444,   # Metasploit default
    5555,   # Common backdoor
    6666,   # IRC / backdoor
    7777,   # Common backdoor
    1234,   # Generic backdoor
    31337,  # Back Orifice
}


# ---------------------------------------------------------------------------
# IOC extraction
# ---------------------------------------------------------------------------

# Regex patterns for IOC extraction
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_RE_URL = re.compile(r"https?://[^\s\"'<>]+")


def extract_network_iocs(analysis_result: dict) -> dict[str, Any]:
    """Pull distinct network IOCs from an analysis result dict.

    Returns a dict with ``ips``, ``domains``, and ``urls`` lists.
    """
    ips: set[str] = set()
    domains: set[str] = set()
    urls: set[str] = set()

    # Connections from strace
    for conn in analysis_result.get("network", []):
        addr = conn.get("address", "")
        if addr and _RE_IPV4.fullmatch(addr):
            ips.add(addr)

    # PCAP data
    pcap = analysis_result.get("pcap", {})

    for dns in pcap.get("dns_queries", []):
        query = dns.get("query", "")
        if query:
            domains.add(query)
        response = dns.get("response", "")
        if response and _RE_IPV4.fullmatch(response):
            ips.add(response)

    for host in pcap.get("http_hosts", []):
        if host:
            domains.add(host)

    for conn_entry in pcap.get("connections", []):
        for field in ("src", "dst"):
            val = conn_entry.get(field, "")
            if val and _RE_IPV4.fullmatch(val):
                ips.add(val)

    # Scan stdout/stderr for additional IOCs
    for text_field in ("stdout", "stderr"):
        text = analysis_result.get(text_field, "")
        if not text:
            continue
        for m in _RE_IPV4.finditer(text):
            ips.add(m.group())
        for m in _RE_URL.finditer(text):
            urls.add(m.group())

    # Filter out private IPs from IOC lists
    external_ips = sorted(ip for ip in ips if not is_private_ip(ip))
    private_ips = sorted(ip for ip in ips if is_private_ip(ip))

    return {
        "ips": external_ips,
        "private_ips": private_ips,
        "domains": sorted(domains),
        "urls": sorted(urls),
        "total": len(external_ips) + len(domains) + len(urls),
    }


# ---------------------------------------------------------------------------
# Main enrichment function
# ---------------------------------------------------------------------------

def enrich_network_data(analysis_result: dict) -> dict[str, Any]:
    """Enhance network data with service mapping, classification, and analysis.

    Parameters
    ----------
    analysis_result:
        The ``result`` JSONB dict stored on an Analysis model instance.

    Returns
    -------
    dict
        Enriched network data suitable for the ``NetworkAnalysisResponse``
        schema.
    """
    enriched: dict[str, Any] = {}

    # --- Enrich connections with service names ---
    connections = analysis_result.get("network", [])
    enriched_conns: list[dict[str, Any]] = []
    for conn in connections:
        port = conn.get("port", 0)
        enriched_conn: dict[str, Any] = {
            **conn,
            "service": PORT_SERVICES.get(port, f"port-{port}"),
            "is_private": is_private_ip(conn.get("address", "")),
            "direction": "outbound",  # strace only captures outbound
        }
        enriched_conns.append(enriched_conn)
    enriched["connections"] = enriched_conns

    # --- Connection summary ---
    enriched["connection_summary"] = {
        "total": len(enriched_conns),
        "external": sum(1 for c in enriched_conns if not c["is_private"]),
        "internal": sum(1 for c in enriched_conns if c["is_private"]),
        "services": sorted(set(c["service"] for c in enriched_conns)),
        "unique_ips": sorted(
            set(c.get("address") for c in enriched_conns if c.get("address"))
        ),
    }

    # --- Enhance DNS data ---
    pcap = analysis_result.get("pcap", {})
    dns_entries = pcap.get("dns_queries", [])
    query_types: dict[str, int] = {}
    for d in dns_entries:
        qtype = d.get("type", "A")
        query_types[qtype] = query_types.get(qtype, 0) + 1

    enriched["dns_analysis"] = {
        "total_queries": len(dns_entries),
        "unique_domains": sorted(
            set(d.get("query", "") for d in dns_entries if d.get("query"))
        ),
        "query_types": query_types,
    }

    # --- HTTP hosts ---
    http_hosts = pcap.get("http_hosts", [])
    enriched["http_hosts"] = sorted(set(http_hosts))

    # --- PCAP statistics ---
    enriched["pcap_stats"] = {
        "total_packets": pcap.get("total_packets", 0),
        "total_bytes": pcap.get("total_bytes", 0),
        "pcap_size": pcap.get("pcap_size", 0),
    }

    # --- Suspicious network indicators ---
    suspicious: list[str] = []

    for conn in enriched_conns:
        port = conn.get("port", 0)
        addr = conn.get("address", "")

        # Non-standard external port
        if port not in PORT_SERVICES and port > 1024 and not conn["is_private"]:
            suspicious.append(
                f"Non-standard port: {addr}:{port}"
            )

        # Known malicious / C2 port
        if port in _SUSPICIOUS_PORTS and not conn["is_private"]:
            suspicious.append(
                f"Suspicious port (commonly used by malware): {addr}:{port}"
            )

        # DNS/HTTP to non-standard port
        if port not in (53, 80, 443, 8080, 8443) and not conn["is_private"]:
            service = conn.get("service", "")
            if service.startswith("port-"):
                suspicious.append(
                    f"Connection to unknown service: {addr}:{port}"
                )

    # DNS-based indicators
    for d in dns_entries:
        domain = d.get("query", "")
        if not domain:
            continue

        # Extremely long domain name (possible data exfiltration / DGA)
        if len(domain) > 50:
            suspicious.append(
                f"Long domain name (possible DGA/tunneling): {domain[:60]}..."
            )

        # Pattern consistent with domain generation algorithms
        if re.match(r"^[a-z0-9]{20,}\.[a-z]{2,4}$", domain):
            suspicious.append(f"Possible DGA domain: {domain}")

        # Excessive sub-domains (possible DNS tunneling)
        if domain.count(".") >= 5:
            suspicious.append(
                f"Deeply nested subdomain (possible DNS tunneling): {domain}"
            )

        # TXT queries can be used for C2 communication
        if d.get("type") == "TXT":
            suspicious.append(f"TXT DNS query (possible C2 channel): {domain}")

    # De-duplicate while preserving order, cap at 30 items
    seen: set[str] = set()
    unique_suspicious: list[str] = []
    for s in suspicious:
        if s not in seen:
            seen.add(s)
            unique_suspicious.append(s)
    enriched["suspicious_indicators"] = unique_suspicious[:30]

    return enriched
