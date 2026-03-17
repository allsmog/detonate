import json
from collections.abc import AsyncIterator
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.models.analysis import Analysis
from detonate.models.conversation import Conversation, Message
from detonate.models.submission import Submission
from detonate.prompts.system import MALWARE_ANALYST_SYSTEM
from detonate.services.llm import BaseLLMProvider, LLMMessage


def _build_submission_context(submission: Submission, analysis: Analysis | None = None) -> str:
    sections = [
        f"You are discussing a file submission with the following metadata:\n"
        f"- Filename: {submission.filename or 'N/A'}\n"
        f"- SHA256: {submission.file_hash_sha256}\n"
        f"- MD5: {submission.file_hash_md5 or 'N/A'}\n"
        f"- File Size: {submission.file_size or 0} bytes\n"
        f"- File Type: {submission.file_type or 'N/A'}\n"
        f"- MIME Type: {submission.mime_type or 'N/A'}\n"
        f"- Tags: {', '.join(submission.tags) if submission.tags else 'None'}\n"
        f"- Current Verdict: {submission.verdict}\n"
        f"- Current Score: {submission.score}/100"
    ]

    if submission.ai_summary:
        sections.append(f"\nAI Summary: {submission.ai_summary[:500]}")

    if analysis and analysis.result:
        result = analysis.result
        procs = result.get("processes", [])
        if procs:
            proc_desc = ", ".join(
                f"PID {p.get('pid')} {p.get('command', '?')}" for p in procs[:10]
            )
            sections.append(f"\nDynamic Analysis - Processes: {proc_desc}")

        net = result.get("network", [])
        if net:
            net_desc = ", ".join(
                f"{n.get('address')}:{n.get('port')}" for n in net[:10]
            )
            sections.append(f"\nNetwork Connections: {net_desc}")

        files = result.get("files_created", [])
        if files:
            file_desc = ", ".join(f.get("path", "?") for f in files[:10])
            sections.append(f"\nFiles Created: {file_desc}")

        pcap = result.get("pcap", {})
        dns = pcap.get("dns_queries", [])
        if dns:
            dns_desc = ", ".join(d.get("query", "?") for d in dns[:10])
            sections.append(f"\nDNS Queries: {dns_desc}")

        ids_alerts = result.get("ids_alerts", [])
        if ids_alerts:
            alert_desc = ", ".join(a.get("signature", "?") for a in ids_alerts[:5])
            sections.append(f"\nIDS Alerts: {alert_desc}")

        mitre = getattr(analysis, 'mitre_techniques', None) or []
        if mitre:
            mitre_desc = ", ".join(
                f"{t.get('technique_id')}: {t.get('name')}" for t in mitre[:10]
            )
            sections.append(f"\nMITRE ATT&CK: {mitre_desc}")

    # Truncate to ~8000 chars
    full = "\n".join(sections)
    return full[:8000]


async def get_or_create_conversation(
    db: AsyncSession, submission_id: UUID, conversation_id: UUID | None = None
) -> Conversation:
    if conversation_id:
        result = await db.execute(
            select(Conversation).where(
                Conversation.id == conversation_id,
                Conversation.submission_id == submission_id,
            )
        )
        conv = result.scalar_one_or_none()
        if conv:
            return conv
    conv = Conversation(submission_id=submission_id, title="New conversation")
    db.add(conv)
    await db.flush()
    await db.refresh(conv)
    return conv


async def send_message_stream(
    db: AsyncSession,
    llm: BaseLLMProvider,
    submission: Submission,
    conversation: Conversation,
    user_content: str,
) -> AsyncIterator[str]:
    # Save user message
    user_msg = Message(
        conversation_id=conversation.id,
        role="user",
        content=user_content,
    )
    db.add(user_msg)
    await db.flush()

    # Load conversation history
    result = await db.execute(
        select(Message)
        .where(Message.conversation_id == conversation.id)
        .order_by(Message.created_at)
    )
    history = result.scalars().all()

    # Load latest analysis for enhanced context
    analysis_result = await db.execute(
        select(Analysis)
        .where(Analysis.submission_id == submission.id, Analysis.status == "completed")
        .order_by(Analysis.completed_at.desc())
        .limit(1)
    )
    latest_analysis = analysis_result.scalar_one_or_none()

    # Build LLM messages
    system = MALWARE_ANALYST_SYSTEM + "\n\n" + _build_submission_context(
        submission, latest_analysis
    )
    llm_messages = [LLMMessage(role=m.role, content=m.content) for m in history]

    # Stream response
    full_content = ""
    async for chunk in llm.stream(llm_messages, system=system):
        full_content += chunk.delta
        yield f"data: {json.dumps({'delta': chunk.delta, 'done': chunk.done})}\n\n"

    # Save assistant message
    assistant_msg = Message(
        conversation_id=conversation.id,
        role="assistant",
        content=full_content,
    )
    db.add(assistant_msg)
    await db.flush()

    yield "data: [DONE]\n\n"
