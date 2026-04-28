"""Generate Suricata IDS rules from PCAP-derived IOCs.

The output uses the unprivileged ``EXTERNAL_NET``/``HOME_NET`` variables
and a fixed SID range (9_000_000–9_999_999) reserved by convention for
auto-generated content.
"""

from __future__ import annotations

import hashlib
from typing import Any


_DEFAULT_SID_BASE = 9_000_000


def _stable_sid(seed: str) -> int:
    h = int(hashlib.md5(seed.encode("utf-8")).hexdigest(), 16)
    return _DEFAULT_SID_BASE + (h % 1_000_000)


def generate_suricata_rules(
    analysis_result: dict[str, Any],
    sample_sha256: str | None = None,
) -> dict[str, Any]:
    pcap = analysis_result.get("pcap", {}) or {}
    domains = [d.get("query") for d in pcap.get("dns_queries", []) or [] if d.get("query")]
    domains = sorted({d.strip(".").lower() for d in domains if d})
    ips: set[str] = set()
    for c in pcap.get("connections", []) or []:
        v = c.get("dst") or ""
        host = v.split(":")[0] if ":" in v else v
        if host and host not in ("127.0.0.1", "0.0.0.0"):
            ips.add(host)
    http_hosts = sorted({h for h in (pcap.get("http_hosts") or []) if h})

    rules: list[str] = []
    msg_prefix = f"DETONATE auto sample:{(sample_sha256 or 'unknown')[:12]}"

    for ip in sorted(ips)[:50]:
        sid = _stable_sid(f"ip:{ip}:{sample_sha256}")
        rules.append(
            f'alert ip $HOME_NET any -> {ip} any '
            f'(msg:"{msg_prefix} contacted IP {ip}"; '
            f'sid:{sid}; rev:1; classtype:trojan-activity; metadata:auto-generated;)'
        )

    for dom in domains[:50]:
        sid = _stable_sid(f"dns:{dom}:{sample_sha256}")
        rules.append(
            f'alert dns $HOME_NET any -> any any '
            f'(msg:"{msg_prefix} DNS lookup {dom}"; '
            f'dns_query; content:"{dom}"; nocase; '
            f'sid:{sid}; rev:1; classtype:trojan-activity; metadata:auto-generated;)'
        )

    for host in http_hosts[:50]:
        sid = _stable_sid(f"http:{host}:{sample_sha256}")
        rules.append(
            f'alert http $HOME_NET any -> $EXTERNAL_NET any '
            f'(msg:"{msg_prefix} HTTP host {host}"; '
            f'flow:established,to_server; http.host; content:"{host}"; nocase; '
            f'sid:{sid}; rev:1; classtype:trojan-activity; metadata:auto-generated;)'
        )

    return {
        "rules": "\n".join(rules) + ("\n" if rules else ""),
        "rule_count": len(rules),
        "indicator_summary": {
            "ips": sorted(ips),
            "domains": domains,
            "http_hosts": http_hosts,
        },
    }
