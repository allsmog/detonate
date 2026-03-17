import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from detonate.api.deps import get_current_user, get_db
from detonate.models.comment import Comment
from detonate.models.submission import Submission
from detonate.models.user import User
from detonate.schemas.comment import (
    CommentCreateRequest,
    CommentListResponse,
    CommentResponse,
    CommentUpdateRequest,
)

logger = logging.getLogger("detonate.api.routes.comments")

router = APIRouter(tags=["comments"])


def _comment_to_response(comment: Comment) -> CommentResponse:
    """Map a Comment ORM object (with user loaded) to CommentResponse."""
    return CommentResponse(
        id=str(comment.id),
        submission_id=str(comment.submission_id),
        user_id=str(comment.user_id),
        user_email=comment.user.email,
        user_display_name=comment.user.display_name,
        content=comment.content,
        created_at=comment.created_at,
        updated_at=comment.updated_at,
    )


async def _get_submission_or_404(db: AsyncSession, submission_id: UUID) -> Submission:
    """Fetch a submission or raise 404."""
    result = await db.execute(
        select(Submission).where(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()
    if submission is None:
        raise HTTPException(status_code=404, detail="Submission not found")
    return submission


@router.post(
    "/submissions/{submission_id}/comments",
    response_model=CommentResponse,
    status_code=201,
)
async def create_comment(
    submission_id: UUID,
    body: CommentCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CommentResponse:
    """Add a comment to a submission."""
    await _get_submission_or_404(db, submission_id)

    comment = Comment(
        submission_id=submission_id,
        user_id=current_user.id,
        content=body.content,
    )
    db.add(comment)
    await db.flush()

    # Reload with user relationship
    result = await db.execute(
        select(Comment)
        .options(selectinload(Comment.user))
        .where(Comment.id == comment.id)
    )
    comment = result.scalar_one()

    logger.info(
        "Comment %s created on submission %s by user %s",
        comment.id,
        submission_id,
        current_user.id,
    )
    return _comment_to_response(comment)


@router.get(
    "/submissions/{submission_id}/comments",
    response_model=CommentListResponse,
)
async def list_comments(
    submission_id: UUID,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
) -> CommentListResponse:
    """List comments on a submission, ordered by creation time ascending."""
    await _get_submission_or_404(db, submission_id)

    # Total count
    count_result = await db.execute(
        select(func.count(Comment.id)).where(
            Comment.submission_id == submission_id
        )
    )
    total = count_result.scalar_one()

    # Paginated results with user info
    result = await db.execute(
        select(Comment)
        .options(selectinload(Comment.user))
        .where(Comment.submission_id == submission_id)
        .order_by(Comment.created_at.asc())
        .limit(limit)
        .offset(offset)
    )
    comments = result.scalars().all()

    return CommentListResponse(
        items=[_comment_to_response(c) for c in comments],
        total=total,
    )


@router.put(
    "/submissions/{submission_id}/comments/{comment_id}",
    response_model=CommentResponse,
)
async def update_comment(
    submission_id: UUID,
    comment_id: UUID,
    body: CommentUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CommentResponse:
    """Edit a comment. Only the comment author can edit."""
    result = await db.execute(
        select(Comment)
        .options(selectinload(Comment.user))
        .where(
            Comment.id == comment_id,
            Comment.submission_id == submission_id,
        )
    )
    comment = result.scalar_one_or_none()
    if comment is None:
        raise HTTPException(status_code=404, detail="Comment not found")

    if comment.user_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Only the comment author can edit this comment",
        )

    comment.content = body.content
    comment.updated_at = text("now()")
    await db.flush()

    # Reload to get the server-generated updated_at value
    await db.refresh(comment)

    logger.info("Comment %s updated by user %s", comment_id, current_user.id)
    return _comment_to_response(comment)


@router.delete(
    "/submissions/{submission_id}/comments/{comment_id}",
    status_code=204,
)
async def delete_comment(
    submission_id: UUID,
    comment_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Delete a comment. The author or a global admin can delete."""
    result = await db.execute(
        select(Comment).where(
            Comment.id == comment_id,
            Comment.submission_id == submission_id,
        )
    )
    comment = result.scalar_one_or_none()
    if comment is None:
        raise HTTPException(status_code=404, detail="Comment not found")

    if comment.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Only the author or an admin can delete this comment",
        )

    await db.delete(comment)
    await db.flush()

    logger.info("Comment %s deleted by user %s", comment_id, current_user.id)
    return Response(status_code=204)
