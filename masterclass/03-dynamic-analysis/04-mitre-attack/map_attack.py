#!/usr/bin/env python3
"""map_attack.py — a teaching-sized clone of Detonate's MITRE rule engine.

Detonate ships 26 behavioral rules in
    api/detonate/services/mitre/rules.py
This file reimplements a handful of them with the SAME approach (process /
network / file rules over the analysis_result dict) so you can see, in ~60
lines, exactly how raw behavior becomes ATT&CK techniques. Run it on the
synthetic result and confirm the mappings; then go read the real engine.

Usage:  python3 map_attack.py sample_analysis.json
"""
from __future__ import annotations

import json
import re
import sys

# (technique_id, name, kind, patterns/ports) — a representative subset.
PROCESS_RULES = [
    ("T1059.004", "Unix Shell", [r"\b(ba)?sh\b", r"/bin/(ba)?sh"]),
    ("T1059.006", "Python", [r"\bpython[23]?\b"]),
    ("T1105", "Ingress Tool Transfer", [r"\bcurl\b", r"\bwget\b"]),
    ("T1222.002", "Linux File Permissions Modification", [r"\bchmod\b"]),
]
# NetworkRule: (id, name, ports, exclude_ports)
NETWORK_RULES = [
    ("T1071.001", "Web Protocols", [80, 443, 8080, 8443], []),
    ("T1071.004", "DNS", [53], []),
    ("T1041", "Exfil Over C2 (non-standard port)", [], [53, 80, 443, 8080, 8443, 22, 123]),
]


def match_processes(result: dict) -> list[dict]:
    hits = []
    for tid, name, patterns in PROCESS_RULES:
        ev = []
        for p in result.get("processes", []):
            hay = f"{p.get('command','')} {' '.join(p.get('args', []))}"
            if any(re.search(pat, hay, re.IGNORECASE) for pat in patterns):
                ev.append(hay.strip())
        if ev:
            hits.append({"technique": tid, "name": name, "evidence": ev})
    return hits


def match_network(result: dict) -> list[dict]:
    hits = []
    conns = result.get("network", {}).get("connections", [])
    dns = result.get("network", {}).get("dns", [])
    for tid, name, ports, exclude in NETWORK_RULES:
        ev = []
        for c in conns:
            port = c.get("dst_port") or c.get("port", 0)
            if exclude and port in exclude:
                continue
            if not ports or port in ports:
                ev.append(f"{c.get('protocol','tcp')}://{c.get('dst_ip','?')}:{port}")
        if 53 in ports:
            ev += [f"dns:{q.get('query', q) if isinstance(q, dict) else q}" for q in dns]
        if ev:
            hits.append({"technique": tid, "name": name, "evidence": ev})
    return hits


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "sample_analysis.json"
    with open(path) as f:
        result = json.load(f)
    hits = match_processes(result) + match_network(result)
    print(f"Mapped {len(hits)} ATT&CK techniques from {path}:\n")
    for h in sorted(hits, key=lambda x: x["technique"]):
        print(f"  {h['technique']:11} {h['name']}")
        for e in h["evidence"][:3]:
            print(f"      <- {e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
