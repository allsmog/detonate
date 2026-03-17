import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_db, require_ai_enabled
from detonate.config import settings
from detonate.models.ai_task import AITask
from detonate.models.submission import Submission
from detonate.schemas.ai import AIStatusResponse, AISummaryResponse, AITaskResponse
from detonate.services.agent import run_agent_analysis
from detonate.services.ai import classify_submission, summarize_submission
from detonate.services.correlation import find_similar_submissions
from detonate.services.llm import BaseLLMProvider, is_provider_configured
from detonate.services.report import generate_report

logger = logging.getLogger("detonate.api.routes.ai")

router = APIRouter()


@router.get("/ai/status", response_model=AIStatusResponse)
async def ai_status() -> AIStatusResponse:
    if not settings.ai_enabled:
        return AIStatusResponse(enabled=False, configured=False)

    model = (
        settings.ollama_model
        if settings.llm_provider == "ollama"
        else settings.anthropic_model
    )
    return AIStatusResponse(
        enabled=True,
        configured=is_provider_configured(),
        provider=settings.llm_provider,
        model=model,
    )


async def _get_submission(db: AsyncSession, submission_id: UUID) -> Submission:
    result = await db.execute(
        select(Submission).where(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    return submission


@router.post(
    "/submissions/{submission_id}/ai/summarize",
    response_model=AITaskResponse,
)
async def request_summarize(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
    llm: BaseLLMProvider = Depends(require_ai_enabled),
) -> AITaskResponse:
    await _get_submission(db, submission_id)
    task = await summarize_submission(db, llm, submission_id)
    return AITaskResponse.model_validate(task)


@router.post(
    "/submissions/{submission_id}/ai/classify",
    response_model=AITaskResponse,
)
async def request_classify(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
    llm: BaseLLMProvider = Depends(require_ai_enabled),
) -> AITaskResponse:
    await _get_submission(db, submission_id)
    task = await classify_submission(db, llm, submission_id)
    return AITaskResponse.model_validate(task)


@router.post(
    "/submissions/{submission_id}/ai/agent",
    response_model=AITaskResponse,
)
async def request_agent_analysis(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
    llm: BaseLLMProvider = Depends(require_ai_enabled),
) -> AITaskResponse:
    submission = await _get_submission(db, submission_id)
    task = await run_agent_analysis(db, llm, submission)
    return AITaskResponse.model_validate(task)


@router.get(
    "/submissions/{submission_id}/ai/tasks/{task_id}",
    response_model=AITaskResponse,
)
async def get_ai_task(
    submission_id: UUID,
    task_id: UUID,
    db: AsyncSession = Depends(get_db),
    _ai: None = Depends(require_ai_enabled),
) -> AITaskResponse:
    result = await db.execute(
        select(AITask).where(
            AITask.id == task_id,
            AITask.submission_id == submission_id,
        )
    )
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="AI task not found")
    return AITaskResponse.model_validate(task)


@router.get(
    "/submissions/{submission_id}/ai/summary",
    response_model=AISummaryResponse,
)
async def get_summary(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
    _ai: None = Depends(require_ai_enabled),
) -> AISummaryResponse:
    submission = await _get_submission(db, submission_id)
    return AISummaryResponse(
        submission_id=submission_id,
        summary=submission.ai_summary,
        generated=submission.ai_summary is not None,
    )


@router.post("/submissions/{submission_id}/ai/report")
async def request_report(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
    llm: BaseLLMProvider = Depends(require_ai_enabled),
) -> dict[str, str]:
    """Generate a comprehensive AI threat report for a submission."""
    submission = await _get_submission(db, submission_id)
    try:
        report = await generate_report(db, llm, submission)
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except Exception:
        logger.exception("Report generation failed for %s", submission_id)
        raise HTTPException(
            status_code=500, detail="Report generation failed unexpectedly"
        )
    return {"report": report}


@router.get("/submissions/{submission_id}/similar")
async def get_similar_submissions(
    submission_id: UUID,
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Find submissions that share IOCs with the given submission."""
    submission = await _get_submission(db, submission_id)
    items = await find_similar_submissions(db, submission, limit=limit)
    return {"items": items}
