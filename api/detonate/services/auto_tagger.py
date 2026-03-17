"""Automatic tag inference for submissions based on analysis results.

Examines file metadata and dynamic analysis output to assign descriptive
tags.  Tags are additive -- existing manually-applied tags are preserved.
"""

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from detonate.models.analysis import Analysis
from detonate.models.submission import Submission

logger = logging.getLogger("detonate.services.auto_tagger")


# ---------------------------------------------------------------------------
# Analysis-based tag rules
# ---------------------------------------------------------------------------
# Each entry is (tag_name, condition_callable).
# The callable receives the analysis ``result`` dict and must return a bool.

TAG_RULES: list[tuple[str, callable]] = [
    (
        "network-active",
        lambda r: bool(r.get("network")),
    ),
    (
        "drops-files",
        lambda r: bool(r.get("files_created")),
    ),
    (
        "modifies-files",
        lambda r: bool(r.get("files_modified")),
    ),
    (
        "deletes-files",
        lambda r: bool(r.get("files_deleted")),
    ),
    (
        "dns-activity",
        lambda r: bool(r.get("pcap", {}).get("dns_queries")),
    ),
    (
        "http-traffic",
        lambda r: bool(r.get("pcap", {}).get("http_hosts")),
    ),
    (
        "ids-alerts",
        lambda r: bool(r.get("ids_alerts")),
    ),
    (
        "uses-shell",
        lambda r: any(
            any(
                sh in p.get("command", "")
                for sh in ("/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash")
            )
            for p in r.get("processes", [])
        ),
    ),
    (
        "downloads-files",
        lambda r: any(
            any(cmd in p.get("command", "") for cmd in ("wget", "curl", "fetch"))
            for p in r.get("processes", [])
        ),
    ),
    (
        "persistence",
        lambda r: any(
            any(
                kw in " ".join([p.get("command", "")] + p.get("args", []))
                for kw in (
                    "crontab",
                    "systemctl enable",
                    "/etc/cron",
                    "/etc/init.d",
                    ".bashrc",
                    ".profile",
                    "rc.local",
                )
            )
            for p in r.get("processes", [])
        ),
    ),
    (
        "privilege-escalation",
        lambda r: any(
            any(
                kw in p.get("command", "")
                for kw in ("sudo", "su ", "pkexec", "doas")
            )
            for p in r.get("processes", [])
        ),
    ),
    (
        "anti-analysis",
        lambda r: any(
            any(
                kw in " ".join([p.get("command", "")] + p.get("args", []))
                for kw in (
                    "/proc/self",
                    "ptrace",
                    "strace",
                    "debugger",
                    "vmware",
                    "virtualbox",
                    "qemu",
                )
            )
            for p in r.get("processes", [])
        ),
    ),
    (
        "packed",
        lambda r: bool(
            r.get("yara", {}).get("sample_matches", [])
        ),
    ),
    (
        "multi-process",
        lambda r: len(r.get("processes", [])) > 3,
    ),
    (
        "high-network-activity",
        lambda r: len(r.get("network", [])) > 10,
    ),
    (
        "pcap-captured",
        lambda r: bool(r.get("pcap")),
    ),
]


# ---------------------------------------------------------------------------
# File-type tag mapping
# ---------------------------------------------------------------------------
# Keys are substrings matched case-insensitively against submission.file_type.

FILE_TYPE_TAGS: dict[str, str] = {
    "PE32+": "pe64-executable",
    "PE32": "pe32-executable",
    "ELF 64-bit": "elf64-binary",
    "ELF 32-bit": "elf32-binary",
    "ELF": "elf-binary",
    "Mach-O": "macho-binary",
    "PDF document": "pdf-document",
    "PDF": "pdf-document",
    "Microsoft Word": "office-document",
    "Microsoft Excel": "office-document",
    "Microsoft PowerPoint": "office-document",
    "Microsoft": "office-document",
    "Rich Text Format": "rtf-document",
    "Zip archive": "archive",
    "RAR archive": "archive",
    "7-zip": "archive",
    "gzip": "archive",
    "tar archive": "archive",
    "Zip": "archive",
    "Java archive": "java-archive",
    "shell script": "script",
    "Python script": "script",
    "Perl script": "script",
    "Ruby script": "script",
    "PHP": "script",
    "JavaScript": "script",
    "Python": "script",
    "ASCII text": "text-file",
    "UTF-8 Unicode text": "text-file",
    "HTML document": "html-file",
    "XML document": "xml-file",
}

# MIME-type based tags (fallback when file_type doesn't match)
MIME_TYPE_TAGS: dict[str, str] = {
    "application/x-executable": "elf-binary",
    "application/x-dosexec": "pe32-executable",
    "application/pdf": "pdf-document",
    "application/zip": "archive",
    "application/x-rar": "archive",
    "application/gzip": "archive",
    "application/java-archive": "java-archive",
    "text/x-shellscript": "script",
    "text/x-python": "script",
    "text/html": "html-file",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def auto_tag_submission(
    db: AsyncSession,
    submission: Submission,
    analysis: Analysis | None = None,
) -> list[str]:
    """Apply automatic tags to a submission based on its metadata and analysis.

    Existing tags on the submission are preserved.  New tags are merged in and
    the combined set is sorted alphabetically.

    Args:
        db: Async database session (will be flushed if tags change).
        submission: The submission to tag.
        analysis: Optional completed analysis whose results drive tagging.

    Returns:
        The updated, sorted list of tags.
    """
    new_tags: set[str] = set(submission.tags or [])

    # --- File-type tags ---
    _apply_file_type_tags(new_tags, submission)

    # --- Analysis-based tags ---
    if analysis and analysis.result:
        result = analysis.result
        for tag_name, condition in TAG_RULES:
            try:
                if condition(result):
                    new_tags.add(tag_name)
            except Exception:
                logger.debug(
                    "Tag rule '%s' raised for submission %s",
                    tag_name,
                    submission.id,
                    exc_info=True,
                )

    # --- Verdict tags ---
    if submission.verdict and submission.verdict != "unknown":
        new_tags.add(f"verdict:{submission.verdict}")

    # --- AI verdict tags ---
    if submission.ai_verdict and submission.ai_verdict != "unknown":
        new_tags.add(f"ai-verdict:{submission.ai_verdict}")

    # --- Score-based tags ---
    if submission.score >= 80:
        new_tags.add("high-risk")
    elif submission.score >= 50:
        new_tags.add("medium-risk")

    tags_list = sorted(new_tags)

    # Only write if the tag set actually changed
    if tags_list != sorted(submission.tags or []):
        submission.tags = tags_list
        await db.flush()
        logger.info(
            "Auto-tagged submission %s with %d tags (was %d)",
            submission.id,
            len(tags_list),
            len(submission.tags or []),
        )

    return tags_list


def _apply_file_type_tags(tags: set[str], submission: Submission) -> None:
    """Add tags based on the file type and MIME type."""
    file_type = submission.file_type or ""
    mime_type = submission.mime_type or ""

    # Check file_type patterns (more specific first due to dict ordering)
    for pattern, tag in FILE_TYPE_TAGS.items():
        if pattern.lower() in file_type.lower():
            tags.add(tag)
            return

    # Fallback to MIME type
    for mime, tag in MIME_TYPE_TAGS.items():
        if mime.lower() == mime_type.lower():
            tags.add(tag)
            return
