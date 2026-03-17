"""LLM prompt builder for MITRE ATT&CK technique classification."""

from __future__ import annotations

# Compact reference of common techniques the LLM should consider.
_TECHNIQUE_REFERENCE = """\
T1059.001 PowerShell | T1059.004 Unix Shell | T1059.006 Python
T1071.001 Web Protocols | T1071.004 DNS | T1041 Exfiltration Over C2
T1082 System Info Discovery | T1083 File/Dir Discovery | T1057 Process Discovery
T1049 System Network Connections Discovery | T1046 Network Service Scanning
T1005 Data from Local System | T1027 Obfuscated Files | T1105 Ingress Tool Transfer
T1070.004 File Deletion | T1053.003 Cron | T1222.002 Linux File Permissions Mod
T1543.002 Systemd Service | T1547.006 Kernel Modules | T1136.001 Local Account
T1562.001 Disable Security Tools | T1497 Sandbox Evasion
T1003.008 /etc/passwd and /etc/shadow | T1021.004 SSH
T1048 Exfiltration Over Alternative Protocol | T1055 Process Injection
T1068 Exploitation for Privilege Escalation | T1070.003 Clear Command History
T1110 Brute Force | T1132 Data Encoding | T1140 Deobfuscate/Decode Files
T1190 Exploit Public-Facing Application | T1203 Exploitation for Client Execution
T1485 Data Destruction | T1486 Data Encrypted for Impact | T1490 Inhibit System Recovery
T1498 Network Denial of Service | T1499 Endpoint Denial of Service
T1518 Software Discovery | T1530 Data from Cloud Storage
T1552.001 Credentials In Files | T1560 Archive Collected Data
T1569.002 Service Execution | T1571 Non-Standard Port | T1573 Encrypted Channel"""


def build_mitre_prompt(
    behavioral_summary: str,
    rule_matches: list[dict],
) -> str:
    """Build an LLM prompt for MITRE ATT&CK classification.

    Parameters
    ----------
    behavioral_summary:
        A textual summary of the sandbox analysis results (processes,
        network activity, file operations, etc.).
    rule_matches:
        Pre-matched techniques from the rule engine, each a dict with
        ``technique_id``, ``name``, ``confidence``, ``evidence``.

    Returns
    -------
    str
        The full prompt to send to the LLM.
    """
    # Format pre-existing rule matches so the LLM can confirm/adjust them
    rule_section = ""
    if rule_matches:
        lines = []
        for m in rule_matches:
            lines.append(
                f"  - {m['technique_id']} {m['name']} "
                f"(confidence={m['confidence']:.1f}): {m.get('evidence', '')}"
            )
        rule_section = (
            "\n## Pre-Matched Techniques (from rule engine)\n"
            + "\n".join(lines)
        )

    prompt = f"""\
You are a malware analyst specializing in MITRE ATT&CK framework mapping.

Analyze the following sandbox behavioral report and identify all MITRE ATT&CK
techniques observed. Consider the full context of what the sample did, not
just individual indicators.

## Behavioral Summary
{behavioral_summary}
{rule_section}

## Reference: Common ATT&CK Techniques
{_TECHNIQUE_REFERENCE}

## Instructions
1. Review the behavioral evidence and identify ALL applicable ATT&CK techniques.
2. For techniques already identified by the rule engine, confirm or adjust the
   confidence score based on the broader context.
3. Identify any ADDITIONAL techniques not caught by the rules.
4. Assign a confidence score (0.0 to 1.0) for each technique based on how
   strong the evidence is.
5. Provide a brief evidence description for each technique.

## Output Format
Return ONLY a JSON array (no markdown fences, no extra text). Each element:
{{
  "technique_id": "T1059.004",
  "technique_name": "Unix Shell",
  "confidence": 0.85,
  "evidence": "Executed /bin/sh -c with encoded payload"
}}

Return an empty array [] if no techniques are detected."""

    return prompt


def build_behavioral_summary(analysis_result: dict) -> str:
    """Build a textual behavioral summary from an analysis result dict.

    This summarises the key observable artefacts so the LLM has enough
    context without receiving the entire raw result.
    """
    parts: list[str] = []

    # Processes
    processes = analysis_result.get("processes", [])
    if processes:
        parts.append(f"### Processes ({len(processes)} total)")
        for proc in processes[:20]:
            cmd = proc.get("command", "unknown")
            args = " ".join(proc.get("args", []))
            pid = proc.get("pid", "?")
            parts.append(f"  PID {pid}: {cmd} {args}".rstrip())

    # Network
    network = analysis_result.get("network", {})
    connections = network.get("connections", [])
    dns = network.get("dns", [])
    http_hosts = network.get("http_hosts", [])

    if connections:
        parts.append(f"\n### Network Connections ({len(connections)} total)")
        for conn in connections[:15]:
            dst = conn.get("dst_ip") or conn.get("address", "?")
            port = conn.get("dst_port") or conn.get("port", "?")
            proto = conn.get("protocol", "tcp")
            parts.append(f"  {proto} -> {dst}:{port}")

    if dns:
        parts.append(f"\n### DNS Queries ({len(dns)} total)")
        for q in dns[:10]:
            name = q if isinstance(q, str) else q.get("query", "?")
            parts.append(f"  {name}")

    if http_hosts:
        parts.append(f"\n### HTTP Hosts ({len(http_hosts)} total)")
        for h in http_hosts[:10]:
            parts.append(f"  {h}")

    # File operations
    files_created = analysis_result.get("files_created", [])
    files_modified = analysis_result.get("files_modified", [])
    files_deleted = analysis_result.get("files_deleted", [])
    file_ops = analysis_result.get("file_operations", [])

    if files_created:
        parts.append(f"\n### Files Created ({len(files_created)} total)")
        for f in files_created[:10]:
            path = f if isinstance(f, str) else f.get("path", "?")
            parts.append(f"  {path}")

    if files_modified:
        parts.append(f"\n### Files Modified ({len(files_modified)} total)")
        for f in files_modified[:10]:
            path = f if isinstance(f, str) else f.get("path", "?")
            parts.append(f"  {path}")

    if files_deleted:
        parts.append(f"\n### Files Deleted ({len(files_deleted)} total)")
        for f in files_deleted[:10]:
            path = f if isinstance(f, str) else f.get("path", "?")
            parts.append(f"  {path}")

    if file_ops:
        parts.append(f"\n### Other File Operations ({len(file_ops)} total)")
        for op in file_ops[:10]:
            operation = op.get("operation", "?")
            path = op.get("path", "?")
            parts.append(f"  {operation}: {path}")

    # IDS alerts
    ids_alerts = analysis_result.get("ids_alerts", [])
    if ids_alerts:
        parts.append(f"\n### IDS Alerts ({len(ids_alerts)} total)")
        for alert in ids_alerts[:10]:
            sig = alert.get("signature", "?")
            sev = alert.get("severity", "?")
            parts.append(f"  [{sev}] {sig}")

    # YARA matches
    yara = analysis_result.get("yara", {})
    yara_matches = yara.get("sample_matches", []) if isinstance(yara, dict) else []
    if yara_matches:
        parts.append(f"\n### YARA Matches ({len(yara_matches)} total)")
        for m in yara_matches[:10]:
            rule_name = m.get("rule", "?")
            parts.append(f"  {rule_name}")

    if not parts:
        return "No behavioral data available."

    return "\n".join(parts)
