"""Generate Sigma rules from dynamic analysis results.

Looks at ``processes`` / ``network`` / ``files_*`` produced by the
sandbox guest agent and emits a Sigma rule (proc_creation logsource for
linux/windows) that matches the observed indicators. The output is
designed for analyst tuning, not direct deployment.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

import yaml  # type: ignore[import-not-found]


def _safe_id(seed: str) -> str:
    h = hashlib.md5(seed.encode("utf-8")).hexdigest()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def generate_sigma_rule(
    analysis_result: dict[str, Any],
    sample_sha256: str | None = None,
    title: str | None = None,
    platform: str = "linux",
) -> dict[str, Any]:
    procs = analysis_result.get("processes", []) or []
    network = analysis_result.get("network", []) or []
    pcap = analysis_result.get("pcap", {}) or {}
    files_created = analysis_result.get("files_created", []) or []

    # Pick distinctive command-line fragments
    cmds: list[str] = []
    for p in procs:
        cmd = p.get("command") or ""
        if not cmd:
            continue
        cmd = cmd.strip()
        if cmd in ("/bin/sh", "/bin/bash", "/usr/bin/python3", "python3"):
            continue
        cmds.append(cmd)
    cmds = list(dict.fromkeys(cmds))[:8]

    # Network indicators
    ips: list[str] = []
    for c in network:
        addr = c.get("address")
        if addr and addr not in ("127.0.0.1", "0.0.0.0"):
            ips.append(addr)
    for c in pcap.get("connections", []) or []:
        for k in ("dst",):
            v = c.get(k)
            if v and ":" in v:
                v = v.split(":")[0]
            if v and v not in ("127.0.0.1", "0.0.0.0"):
                ips.append(v)
    domains = [d.get("query") for d in pcap.get("dns_queries", []) or [] if d.get("query")]
    domains = list(dict.fromkeys(domains))[:10]
    ips = list(dict.fromkeys(ips))[:10]

    # Distinctive dropped paths
    drops: list[str] = []
    for f in files_created:
        p = f.get("path")
        if not p:
            continue
        if any(p.startswith(prefix) for prefix in ("/tmp/", "/var/tmp/", "/home/")):
            drops.append(p)
    drops = list(dict.fromkeys(drops))[:8]

    seed = "|".join(cmds + ips + domains + drops) or sample_sha256 or "empty"
    rule_id = _safe_id(seed)

    rule: dict[str, Any] = {
        "title": title or f"Detonate auto-generated detection ({sample_sha256[:12] if sample_sha256 else 'unknown'})",
        "id": rule_id,
        "status": "experimental",
        "description": "Auto-generated from observed sandbox behavior. Tune before deployment.",
        "author": "detonate-auto",
        "logsource": {
            "category": "process_creation",
            "product": platform,
        },
        "detection": {},
        "falsepositives": ["Legitimate administrative tools matching the same command-line patterns"],
        "level": "medium",
        "tags": [],
    }

    selection: dict[str, Any] = {}
    if cmds:
        selection["CommandLine|contains"] = cmds
    if drops:
        selection["TargetFilename|contains"] = drops

    network_selection: dict[str, Any] = {}
    if ips:
        network_selection["DestinationIp"] = ips
    if domains:
        network_selection["DestinationHostname"] = domains

    if selection and network_selection:
        rule["detection"] = {
            "selection_proc": selection,
            "selection_net": network_selection,
            "condition": "selection_proc or selection_net",
        }
    elif selection:
        rule["detection"] = {"selection": selection, "condition": "selection"}
    elif network_selection:
        # switch logsource to network for accuracy
        rule["logsource"] = {"category": "network_connection", "product": platform}
        rule["detection"] = {"selection": network_selection, "condition": "selection"}
    else:
        rule["detection"] = {
            "selection": {"_placeholder": "no distinctive indicators observed"},
            "condition": "selection",
        }

    sample_short = (sample_sha256 or "")[:64]
    if sample_short:
        rule["tags"].append(f"sample:{sample_short}")

    text = yaml.safe_dump(rule, sort_keys=False, default_flow_style=False)
    # Sigma convention: lowercase booleans stay quoted-free; yaml is fine.
    return {
        "rule": rule,
        "sigma": text,
        "id": rule_id,
        "indicator_count": len(cmds) + len(drops) + len(ips) + len(domains),
    }
