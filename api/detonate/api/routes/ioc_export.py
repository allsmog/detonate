from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_db
from detonate.models.submission import Submission
from detonate.services.ioc_export import (
    export_csv,
    export_json,
    export_stix,
    extract_iocs,
)

router = APIRouter(tags=["ioc-export"])


async def _get_submission(submission_id: UUID, db: AsyncSession) -> Submission:
    """Look up a submission or raise 404."""
    result = await db.execute(
        select(Submission).where(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()
    if submission is None:
        raise HTTPException(status_code=404, detail="Submission not found")
    return submission


@router.get("/submissions/{submission_id}/iocs")
async def get_iocs(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Extract IOCs from a submission and its analyses."""
    submission = await _get_submission(submission_id, db)
    iocs = await extract_iocs(db, submission)
    return iocs


@router.get("/submissions/{submission_id}/iocs/csv")
async def get_iocs_csv(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Export IOCs as a CSV file download."""
    submission = await _get_submission(submission_id, db)
    iocs = await extract_iocs(db, submission)
    csv_content = export_csv(iocs)

    filename = f"iocs-{submission.file_hash_sha256[:12]}.csv"
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/submissions/{submission_id}/iocs/stix")
async def get_iocs_stix(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Export IOCs as a STIX 2.1 bundle."""
    submission = await _get_submission(submission_id, db)
    iocs = await extract_iocs(db, submission)
    bundle = export_stix(iocs, str(submission_id))
    return bundle


@router.get("/submissions/{submission_id}/iocs/json")
async def get_iocs_json(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Export IOCs as a formatted JSON file download."""
    submission = await _get_submission(submission_id, db)
    iocs = await extract_iocs(db, submission)
    json_content = export_json(iocs)

    filename = f"iocs-{submission.file_hash_sha256[:12]}.json"
    return Response(
        content=json_content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
