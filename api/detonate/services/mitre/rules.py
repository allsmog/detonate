"""Behavioral rule engine for MITRE ATT&CK technique detection.

Each rule inspects the ``analysis_result`` dictionary produced by the dynamic
analysis sandbox and returns evidence when a known behavioral pattern matches.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger("detonate.services.mitre.rules")


# ---------------------------------------------------------------------------
# Base rule classes
# ---------------------------------------------------------------------------

@dataclass
class BehavioralRule:
    """Base class for all behavioral detection rules."""

    technique_id: str
    name: str
    description: str

    def match(self, analysis_result: dict) -> dict | None:
        """Return an evidence dict if the rule matches, ``None`` otherwise."""
        raise NotImplementedError


@dataclass
class ProcessRule(BehavioralRule):
    """Match against process commands/arguments."""

    patterns: list[str] = field(default_factory=list)

    def match(self, analysis_result: dict) -> dict | None:
        processes = analysis_result.get("processes", [])
        matched_commands: list[str] = []

        for proc in processes:
            command = proc.get("command", "")
            args = " ".join(proc.get("args", []))
            haystack = f"{command} {args}"

            for pattern in self.patterns:
                if re.search(pattern, haystack, re.IGNORECASE):
                    matched_commands.append(haystack.strip())
                    break

        if matched_commands:
            # Deduplicate and limit evidence length
            unique = list(dict.fromkeys(matched_commands))[:5]
            return {
                "matched_processes": unique,
                "count": len(matched_commands),
            }
        return None


@dataclass
class NetworkRule(BehavioralRule):
    """Match against network connections."""

    ports: list[int] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    exclude_ports: list[int] = field(default_factory=list)

    def match(self, analysis_result: dict) -> dict | None:
        connections = analysis_result.get("network", {}).get("connections", [])
        dns_queries = analysis_result.get("network", {}).get("dns", [])
        matched: list[str] = []

        for conn in connections:
            port = conn.get("dst_port") or conn.get("port", 0)
            protocol = conn.get("protocol", "").lower()
            address = conn.get("dst_ip") or conn.get("address", "")

            if self.exclude_ports and port in self.exclude_ports:
                continue

            port_match = not self.ports or port in self.ports
            proto_match = not self.protocols or protocol in self.protocols
            if port_match and proto_match:
                matched.append(f"{protocol}://{address}:{port}")

        # Also check DNS if matching port 53
        if 53 in self.ports:
            for query in dns_queries:
                name = query if isinstance(query, str) else query.get("query", "")
                if name:
                    matched.append(f"dns:{name}")

        if matched:
            unique = list(dict.fromkeys(matched))[:5]
            return {
                "matched_connections": unique,
                "count": len(matched),
            }
        return None


@dataclass
class FileRule(BehavioralRule):
    """Match against file system operations."""

    path_patterns: list[str] = field(default_factory=list)
    operations: list[str] = field(default_factory=list)

    def match(self, analysis_result: dict) -> dict | None:
        file_ops = analysis_result.get("file_operations", [])
        files_created = analysis_result.get("files_created", [])
        files_modified = analysis_result.get("files_modified", [])
        files_deleted = analysis_result.get("files_deleted", [])

        # Aggregate all file paths with their operations
        all_paths: list[tuple[str, str]] = []
        for op in file_ops:
            all_paths.append((op.get("path", ""), op.get("operation", "")))
        for p in files_created:
            path = p if isinstance(p, str) else p.get("path", "")
            all_paths.append((path, "create"))
        for p in files_modified:
            path = p if isinstance(p, str) else p.get("path", "")
            all_paths.append((path, "modify"))
        for p in files_deleted:
            path = p if isinstance(p, str) else p.get("path", "")
            all_paths.append((path, "delete"))

        matched_files: list[str] = []
        for path, operation in all_paths:
            if not path:
                continue
            # Filter by operation type if specified
            if self.operations and operation.lower() not in [
                o.lower() for o in self.operations
            ]:
                continue
            for pattern in self.path_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    matched_files.append(f"{operation}:{path}")
                    break

        if matched_files:
            unique = list(dict.fromkeys(matched_files))[:5]
            return {
                "matched_files": unique,
                "count": len(matched_files),
            }
        return None


# ---------------------------------------------------------------------------
# Rule definitions (20+ rules)
# ---------------------------------------------------------------------------

RULES: list[BehavioralRule] = [
    # --- Execution ---
    ProcessRule(
        technique_id="T1059.004",
        name="Unix Shell",
        description="Command execution via Unix shell interpreters",
        patterns=[
            r"\b(ba)?sh\b",
            r"/bin/(ba)?sh",
            r"\bsh\s+-c\b",
            r"/usr/bin/env\s+(ba)?sh",
        ],
    ),
    ProcessRule(
        technique_id="T1059.006",
        name="Python",
        description="Command execution via Python interpreter",
        patterns=[
            r"\bpython[23]?\b",
            r"/usr/bin/python",
            r"/usr/bin/env\s+python",
        ],
    ),
    ProcessRule(
        technique_id="T1059.001",
        name="PowerShell",
        description="Command execution via PowerShell",
        patterns=[
            r"\bpwsh\b",
            r"\bpowershell\b",
        ],
    ),

    # --- Discovery ---
    ProcessRule(
        technique_id="T1082",
        name="System Information Discovery",
        description="Gathering system configuration and version info",
        patterns=[
            r"\buname\b",
            r"\bhostname\b",
            r"/etc/hostname",
            r"/proc/version",
            r"\blsb_release\b",
            r"\bcat\s+/etc/(os-release|issue|lsb-release)",
        ],
    ),
    ProcessRule(
        technique_id="T1083",
        name="File and Directory Discovery",
        description="Enumerating files and directories on the system",
        patterns=[
            r"\bls\s",
            r"\bfind\s",
            r"\bdir\b",
            r"\btree\b",
            r"\blocate\b",
        ],
    ),
    ProcessRule(
        technique_id="T1057",
        name="Process Discovery",
        description="Enumerating running processes",
        patterns=[
            r"\bps\s",
            r"\bps$",
            r"\btop\b",
            r"\bhtop\b",
            r"/proc/\d+/(status|cmdline|maps)",
        ],
    ),
    FileRule(
        technique_id="T1057",
        name="Process Discovery (File)",
        description="Reading process information from /proc",
        path_patterns=[
            r"^/proc/\d+/(status|cmdline|maps|environ)",
        ],
        operations=["read", "open"],
    ),
    ProcessRule(
        technique_id="T1049",
        name="System Network Connections Discovery",
        description="Enumerating network connections",
        patterns=[
            r"\bnetstat\b",
            r"\bss\b\s+-",
            r"/proc/net/(tcp|udp|raw)",
        ],
    ),

    # --- Collection ---
    ProcessRule(
        technique_id="T1005",
        name="Data from Local System",
        description="Accessing sensitive local files for data collection",
        patterns=[
            r"/etc/shadow",
            r"/etc/passwd",
            r"/etc/sudoers",
            r"\bcat\s+/home/",
            r"\bcat\s+/root/",
        ],
    ),
    FileRule(
        technique_id="T1005",
        name="Data from Local System (File)",
        description="Reading sensitive files for data collection",
        path_patterns=[
            r"^/etc/(shadow|passwd|sudoers)",
            r"^/home/.*\.(ssh|gnupg|bash_history|profile)",
            r"^/root/",
        ],
        operations=["read", "open"],
    ),

    # --- Command and Control ---
    NetworkRule(
        technique_id="T1071.001",
        name="Web Protocols",
        description="Communication over standard web protocols (HTTP/HTTPS)",
        ports=[80, 443, 8080, 8443],
    ),
    NetworkRule(
        technique_id="T1071.004",
        name="DNS",
        description="Communication via DNS protocol",
        ports=[53],
    ),

    # --- Exfiltration ---
    NetworkRule(
        technique_id="T1041",
        name="Exfiltration Over C2 Channel",
        description="Outbound connections to non-standard ports (potential exfiltration)",
        exclude_ports=[53, 80, 443, 8080, 8443, 22, 123],
        ports=[],  # matches all ports not excluded
    ),

    # --- Defense Evasion ---
    ProcessRule(
        technique_id="T1027",
        name="Obfuscated Files or Information",
        description="Use of encoding/obfuscation tools to hide data",
        patterns=[
            r"\bbase64\b",
            r"\bxxd\b",
            r"\bopenssl\s+(enc|base64)",
            r"eval\s*\(",
        ],
    ),
    ProcessRule(
        technique_id="T1070.004",
        name="File Deletion",
        description="Deleting files to remove indicators of compromise",
        patterns=[
            r"\brm\s",
            r"\brm\b$",
            r"\bunlink\b",
            r"\bshred\b",
            r"\bwipe\b",
        ],
    ),
    ProcessRule(
        technique_id="T1562.001",
        name="Disable or Modify Tools",
        description="Disabling security tools or logging",
        patterns=[
            r"\bkill\s.*-9",
            r"\bsystemctl\s+(stop|disable)\s+(apparmor|auditd|fail2ban|ufw|firewalld|iptables)",
            r"\bufw\s+disable",
            r"\biptables\s+-F",
            r"\bsetenforce\s+0",
            r"\bchkconfig\s+.*off",
            r"service\s+(auditd|apparmor|fail2ban)\s+stop",
        ],
    ),
    ProcessRule(
        technique_id="T1497",
        name="Virtualization/Sandbox Evasion",
        description="Checking for virtual machine or sandbox artifacts",
        patterns=[
            r"/proc/cpuinfo",
            r"/sys/class/dmi/id",
            r"\bsystemd-detect-virt\b",
            r"\bdmidecode\b",
            r"\bvboxmanage\b",
            r"VBOX|VMWARE|QEMU|KVM|VIRTUAL",
        ],
    ),

    # --- Ingress Tool Transfer ---
    ProcessRule(
        technique_id="T1105",
        name="Ingress Tool Transfer",
        description="Downloading files from external sources",
        patterns=[
            r"\bwget\b",
            r"\bcurl\b.*(-o|-O|--output)",
            r"\bcurl\b.*http",
            r"\bfetch\b",
            r"\bscp\b",
            r"\bsftp\b",
        ],
    ),

    # --- Persistence ---
    ProcessRule(
        technique_id="T1053.003",
        name="Cron",
        description="Scheduling tasks via cron for persistence",
        patterns=[
            r"\bcrontab\b",
            r"/etc/cron",
            r"/var/spool/cron",
        ],
    ),
    FileRule(
        technique_id="T1053.003",
        name="Cron (File)",
        description="Writing to cron directories for persistence",
        path_patterns=[
            r"^/etc/cron\.(d|daily|hourly|weekly|monthly)/",
            r"^/var/spool/cron/",
            r"^/etc/crontab$",
        ],
        operations=["create", "modify", "write"],
    ),
    ProcessRule(
        technique_id="T1543.002",
        name="Systemd Service",
        description="Creating or modifying systemd services for persistence",
        patterns=[
            r"\bsystemctl\s+(enable|start|daemon-reload)",
            r"/etc/systemd/system/",
            r"/usr/lib/systemd/",
        ],
    ),
    FileRule(
        technique_id="T1543.002",
        name="Systemd Service (File)",
        description="Writing systemd unit files for persistence",
        path_patterns=[
            r"^/etc/systemd/system/.*\.service$",
            r"^/usr/lib/systemd/system/.*\.service$",
        ],
        operations=["create", "modify", "write"],
    ),

    # --- Privilege Escalation ---
    ProcessRule(
        technique_id="T1222.002",
        name="Linux File Permissions Modification",
        description="Changing file permissions or ownership",
        patterns=[
            r"\bchmod\b",
            r"\bchown\b",
            r"\bchgrp\b",
            r"\bsetfacl\b",
        ],
    ),
    ProcessRule(
        technique_id="T1547.006",
        name="Kernel Modules and Extensions",
        description="Loading kernel modules for persistence or rootkit installation",
        patterns=[
            r"\binsmod\b",
            r"\bmodprobe\b",
            r"\brmmod\b",
            r"\blsmod\b",
            r"/lib/modules/",
        ],
    ),

    # --- Account Creation ---
    ProcessRule(
        technique_id="T1136.001",
        name="Local Account",
        description="Creating local user accounts",
        patterns=[
            r"\buseradd\b",
            r"\badduser\b",
            r"\bgroupadd\b",
            r"\busermod\b",
        ],
    ),

    # --- Network Scanning ---
    ProcessRule(
        technique_id="T1046",
        name="Network Service Scanning",
        description="Scanning for network services and open ports",
        patterns=[
            r"\bnmap\b",
            r"\bmasscan\b",
            r"\bzmap\b",
            r"\bnetcat\b",
            r"\bnc\s+-z",
            r"\bnc\b.*\d+\s*-\s*\d+",
        ],
    ),
]


# ---------------------------------------------------------------------------
# Custom match logic for T1041 (Exfiltration Over C2 Channel)
# ---------------------------------------------------------------------------
# The default NetworkRule for T1041 uses exclude_ports with empty ports list,
# which means it matches *any* connection not on excluded ports.  We override
# the match method via a subclass to only trigger when there are actual
# outbound connections to non-standard ports.

class _ExfiltrationRule(NetworkRule):
    """Special-case: match outbound connections to non-standard ports."""

    def match(self, analysis_result: dict) -> dict | None:
        connections = analysis_result.get("network", {}).get("connections", [])
        standard_ports = {53, 80, 443, 8080, 8443, 22, 123}
        matched: list[str] = []

        for conn in connections:
            port = conn.get("dst_port") or conn.get("port", 0)
            if port and port not in standard_ports:
                address = conn.get("dst_ip") or conn.get("address", "unknown")
                protocol = conn.get("protocol", "tcp").lower()
                matched.append(f"{protocol}://{address}:{port}")

        if matched:
            unique = list(dict.fromkeys(matched))[:5]
            return {
                "matched_connections": unique,
                "count": len(matched),
            }
        return None


# Replace the generic T1041 rule with the specialized version
for _i, _rule in enumerate(RULES):
    if _rule.technique_id == "T1041" and isinstance(_rule, NetworkRule):
        RULES[_i] = _ExfiltrationRule(
            technique_id="T1041",
            name="Exfiltration Over C2 Channel",
            description="Outbound connections to non-standard ports (potential exfiltration)",
        )
        break


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _compute_confidence(rule: BehavioralRule, evidence: dict) -> float:
    """Heuristic confidence score based on the number of matches."""
    count = evidence.get("count", 1)
    if count >= 5:
        return 0.9
    if count >= 3:
        return 0.8
    if count >= 2:
        return 0.7
    return 0.6


def evaluate_rules(analysis_result: dict) -> list[dict]:
    """Run all behavioural rules against an analysis result.

    Returns a list of dicts, each containing:
    - ``technique_id``
    - ``name``
    - ``confidence`` (float 0-1)
    - ``evidence`` (str - human-readable summary)
    - ``source``: always ``"rule"``
    """
    if not analysis_result:
        return []

    matches: list[dict] = []
    # Track best confidence per technique to deduplicate
    seen: dict[str, dict] = {}

    for rule in RULES:
        try:
            evidence = rule.match(analysis_result)
        except Exception:
            logger.debug(
                "Rule %s (%s) raised an exception",
                rule.technique_id, rule.name, exc_info=True,
            )
            continue

        if evidence is None:
            continue

        confidence = _compute_confidence(rule, evidence)

        # Build human-readable evidence string
        parts: list[str] = []
        for key in ("matched_processes", "matched_connections", "matched_files"):
            items = evidence.get(key, [])
            if items:
                parts.extend(items[:3])
        count = evidence.get("count", 0)
        evidence_str = "; ".join(parts)
        if count > 3:
            evidence_str += f" (+{count - 3} more)"

        tid = rule.technique_id
        if tid not in seen or confidence > seen[tid]["confidence"]:
            seen[tid] = {
                "technique_id": tid,
                "name": rule.name,
                "confidence": confidence,
                "evidence": evidence_str,
                "source": "rule",
            }

    matches = sorted(seen.values(), key=lambda m: m["confidence"], reverse=True)
    return matches
