"""ATT&CK STIX 2.1 data loader.

Parses the MITRE ATT&CK Enterprise JSON bundle and provides lookup
functions for techniques, tactics, and free-text search.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger("detonate.services.mitre.data")

MITRE_DATA_PATH = "sandbox/mitre/enterprise-attack.json"

# Ordered list of the 14 ATT&CK Enterprise tactics (kill-chain phases).
ATTACK_TACTICS: list[str] = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

# Module-level cache
_techniques: dict[str, dict] | None = None


def load_techniques() -> dict[str, dict]:
    """Load and parse enterprise-attack.json (STIX 2.1).

    Returns a dict keyed by technique_id (e.g. ``"T1059.004"``) with values
    containing ``name``, ``description``, ``tactics``, ``platforms``, and
    ``url``.  Results are cached after the first successful load.
    """
    global _techniques
    if _techniques is not None:
        return _techniques

    path = Path(MITRE_DATA_PATH)
    if not path.exists():
        logger.warning("MITRE ATT&CK data file not found at %s", path)
        _techniques = {}
        return _techniques

    try:
        with path.open("r", encoding="utf-8") as fh:
            bundle = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Failed to load MITRE ATT&CK data: %s", exc)
        _techniques = {}
        return _techniques

    techniques: dict[str, dict] = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        # Extract technique ID and URL from external_references
        technique_id: str | None = None
        url: str = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                url = ref.get("url", "")
                break

        if not technique_id:
            continue

        # Extract tactics from kill_chain_phases
        tactics: list[str] = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                phase_name = phase.get("phase_name", "")
                if phase_name:
                    tactics.append(phase_name)

        # Truncate description to first 200 characters
        raw_description = obj.get("description", "")
        description = raw_description[:200].rstrip()
        if len(raw_description) > 200:
            description += "..."

        techniques[technique_id] = {
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "description": description,
            "tactics": tactics,
            "platforms": obj.get("x_mitre_platforms", []),
            "url": url,
        }

    _techniques = techniques
    logger.info("Loaded %d MITRE ATT&CK techniques", len(techniques))
    return _techniques


def get_technique(technique_id: str) -> dict | None:
    """Return a single technique by ID, or ``None`` if not found."""
    return load_techniques().get(technique_id)


def search_techniques(query: str) -> list[dict]:
    """Case-insensitive search across technique name and description."""
    if not query:
        return list(load_techniques().values())

    query_lower = query.lower()
    results: list[dict] = []
    for tech in load_techniques().values():
        name = tech.get("name", "").lower()
        desc = tech.get("description", "").lower()
        tid = tech.get("technique_id", "").lower()
        if query_lower in name or query_lower in desc or query_lower in tid:
            results.append(tech)
    return results


def get_all_tactics() -> list[str]:
    """Return the 14 ATT&CK Enterprise tactics in kill-chain order."""
    return list(ATTACK_TACTICS)
