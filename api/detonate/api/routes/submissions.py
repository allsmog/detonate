import logging
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_current_user_optional, get_db, get_storage
from detonate.models.submission import Submission
from detonate.schemas.submission import SubmissionListResponse, SubmissionResponse
from detonate.services.storage import StorageService
from detonate.services.submission import create_submission

logger = logging.getLogger("detonate.api.routes.submissions")

router = APIRouter()


@router.post("/submit", response_model=SubmissionResponse, status_code=201)
@router.post("/submissions", response_model=SubmissionResponse, status_code=201)
async def submit_file(
    file: UploadFile,
    tags: str = Form(default=""),
    db: AsyncSession = Depends(get_db),
    storage: StorageService = Depends(get_storage),
    user=Depends(get_current_user_optional),
) -> SubmissionResponse:
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
    try:
        submission = await create_submission(file, tag_list, db, storage)
    except ValueError as e:
        raise HTTPException(status_code=413, detail=str(e))
    if user:
        submission.user_id = user.id
        await db.flush()
    return SubmissionResponse.model_validate(submission)


@router.get("/submissions", response_model=SubmissionListResponse)
async def list_submissions(
    limit: int = 20,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
) -> SubmissionListResponse:
    # Get total count
    count_result = await db.execute(select(func.count(Submission.id)))
    total = count_result.scalar_one()

    # Get paginated results
    query = (
        select(Submission)
        .order_by(Submission.submitted_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await db.execute(query)
    submissions = result.scalars().all()

    return SubmissionListResponse(
        items=[SubmissionResponse.model_validate(s) for s in submissions],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/submissions/{submission_id}", response_model=SubmissionResponse)
async def get_submission(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> SubmissionResponse:
    result = await db.execute(
        select(Submission).where(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()
    if submission is None:
        raise HTTPException(status_code=404, detail="Submission not found")
    return SubmissionResponse.model_validate(submission)


