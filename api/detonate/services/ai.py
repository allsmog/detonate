import json
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.models.ai_task import AITask
from detonate.models.submission import Submission
from detonate.prompts.classify import build_classify_prompt
from detonate.prompts.summarize import build_summarize_prompt
from detonate.prompts.system import MALWARE_ANALYST_SYSTEM
from detonate.services.llm import BaseLLMProvider, LLMMessage


async def get_submission_or_raise(db: AsyncSession, submission_id: UUID) -> Submission:
    result = await db.execute(
        select(Submission).where(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()
    if not submission:
        raise ValueError(f"Submission {submission_id} not found")
    return submission


async def summarize_submission(
    db: AsyncSession, llm: BaseLLMProvider, submission_id: UUID
) -> AITask:
    submission = await get_submission_or_raise(db, submission_id)

    task = AITask(
        submission_id=submission_id,
        task_type="summarize",
        status="running",
        started_at=datetime.now(timezone.utc),
    )
    db.add(task)
    await db.flush()

    try:
        prompt = build_summarize_prompt(submission)
        resp = await llm.complete(
            messages=[LLMMessage(role="user", content=prompt)],
            system=MALWARE_ANALYST_SYSTEM,
        )

        task.status = "completed"
        task.output_data = {"summary": resp.content}
        task.model_used = resp.model
        task.tokens_used = resp.usage
        task.completed_at = datetime.now(timezone.utc)

        # Cache on submission
        submission.ai_summary = resp.content
        submission.ai_analyzed_at = datetime.now(timezone.utc)

    except Exception as e:
        task.status = "failed"
        task.error = str(e)
        task.completed_at = datetime.now(timezone.utc)

    await db.flush()
    await db.refresh(task)
    return task


async def classify_submission(
    db: AsyncSession, llm: BaseLLMProvider, submission_id: UUID
) -> AITask:
    submission = await get_submission_or_raise(db, submission_id)

    task = AITask(
        submission_id=submission_id,
        task_type="classify",
        status="running",
        started_at=datetime.now(timezone.utc),
    )
    db.add(task)
    await db.flush()

    try:
        prompt = build_classify_prompt(submission)
        resp = await llm.complete(
            messages=[LLMMessage(role="user", content=prompt)],
            system=MALWARE_ANALYST_SYSTEM,
        )

        # Parse JSON from response
        content = resp.content.strip()
        # Strip markdown fences if present
        if content.startswith("```"):
            content = content.split("\n", 1)[1].rsplit("```", 1)[0].strip()

        classification = json.loads(content)

        task.status = "completed"
        task.output_data = classification
        task.model_used = resp.model
        task.tokens_used = resp.usage
        task.completed_at = datetime.now(timezone.utc)

        # Cache on submission
        verdict = classification.get("verdict", "unknown")
        if verdict in ("clean", "suspicious", "malicious", "unknown"):
            submission.ai_verdict = verdict
        score = classification.get("score")
        if isinstance(score, int) and 0 <= score <= 100:
            submission.ai_score = score
        submission.ai_analyzed_at = datetime.now(timezone.utc)

    except Exception as e:
        task.status = "failed"
        task.error = str(e)
        task.completed_at = datetime.now(timezone.utc)

    await db.flush()
    await db.refresh(task)
    return task
