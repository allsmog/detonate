import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_current_user_optional, get_db, get_storage
from detonate.schemas.submission import SubmissionResponse
from detonate.services.storage import StorageService
from detonate.services.url_submission import submit_url

logger = logging.getLogger("detonate.api.routes.url_submit")

router = APIRouter(tags=["submissions"])


class URLSubmitRequest(BaseModel):
    url: str = Field(..., description="URL to download and submit for analysis")
    tags: str = Field(default="", description="Comma-separated tags")


@router.post("/submit-url", response_model=SubmissionResponse, status_code=201)
async def submit_url_endpoint(
    body: URLSubmitRequest,
    db: AsyncSession = Depends(get_db),
    storage: StorageService = Depends(get_storage),
    user=Depends(get_current_user_optional),
) -> SubmissionResponse:
    """Download content from a URL and create a new submission."""
    tag_list = [t.strip() for t in body.tags.split(",") if t.strip()] if body.tags else []

    try:
        submission = await submit_url(body.url, tag_list, db, storage)
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to download URL: HTTP {exc.response.status_code}",
        )
    except httpx.ConnectError:
        raise HTTPException(
            status_code=502,
            detail="Failed to connect to the provided URL",
        )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail="Timeout while downloading from the provided URL",
        )
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected error during URL submission: %s", body.url)
        raise HTTPException(
            status_code=502,
            detail=f"Failed to download URL: {exc}",
        )

    if user:
        submission.user_id = user.id
        await db.flush()

    return SubmissionResponse.model_validate(submission)
