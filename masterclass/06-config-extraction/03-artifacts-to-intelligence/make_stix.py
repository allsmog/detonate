#!/usr/bin/env python3
"""make_stix.py — Module 6.3: turn extracted IOCs into a STIX 2.1 bundle.

Mirrors the structure of Detonate's own exporter
(api/detonate/services/ioc_export.py :: export_stix) so you see how raw findings
become a shareable, machine-readable intelligence package.

Pipe in the extractor's JSON, get a STIX bundle out:
  python3 ../02-building-extractor/extract_config.py ./configbot \
    | python3 make_stix.py

IOCs are DEFANGED in human-readable docs (SAFETY.md) but kept live inside the
STIX pattern so downstream tooling can consume them — that's the format's job.
"""
from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone


def indicator(pattern: str, name: str, description: str) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": now,
        "modified": now,
        "name": name,
        "description": description,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": now,
    }


def build_bundle(cfg: dict) -> dict:
    objects = []
    campaign = cfg.get("id", "unknown")
    for c2 in cfg.get("c2", []):
        host = c2.get("host", "")
        if not host:
            continue
        # domain pattern (a real pipeline would distinguish domain vs ip)
        objects.append(indicator(
            pattern=f"[domain-name:value = '{host}']",
            name=f"C2 domain {host}",
            description=f"C2 endpoint from configbot campaign {campaign}",
        ))
    if "mutex" in cfg:
        objects.append(indicator(
            pattern=f"[mutex:name = '{cfg['mutex']}']",
            name="Mutex",
            description=f"Mutex from configbot campaign {campaign}",
        ))
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def main() -> int:
    cfg = json.load(sys.stdin)
    bundle = build_bundle(cfg)
    print(json.dumps(bundle, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
