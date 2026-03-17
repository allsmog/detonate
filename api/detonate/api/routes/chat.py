from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_db, require_ai_enabled
from detonate.models.conversation import Conversation, Message
from detonate.models.submission import Submission
from detonate.schemas.chat import (
    ChatMessageRequest,
    ConversationListResponse,
    ConversationResponse,
    MessageResponse,
)
from detonate.services.chat import get_or_create_conversation, send_message_stream
from detonate.services.llm import BaseLLMProvider

router = APIRouter()


async def _get_submission(db: AsyncSession, submission_id: UUID) -> Submission:
    result = await db.execute(
        select(Submission).where(Submission.id == submission_id)
    )
    submission = result.scalar_one_or_none()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    return submission


@router.post(
    "/submissions/{submission_id}/chat/conversations",
    response_model=ConversationResponse,
    status_code=201,
)
async def create_conversation(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
    _ai: None = Depends(require_ai_enabled),
) -> ConversationResponse:
    await _get_submission(db, submission_id)
    conv = await get_or_create_conversation(db, submission_id)
    return ConversationResponse.model_validate(conv)


@router.get(
    "/submissions/{submission_id}/chat/conversations",
    response_model=ConversationListResponse,
)
async def list_conversations(
    submission_id: UUID,
    db: AsyncSession = Depends(get_db),
    _ai: None = Depends(require_ai_enabled),
) -> ConversationListResponse:
    result = await db.execute(
        select(Conversation)
        .where(Conversation.submission_id == submission_id)
        .order_by(Conversation.created_at.desc())
    )
    convs = result.scalars().all()
    return ConversationListResponse(
        items=[ConversationResponse.model_validate(c) for c in convs]
    )


@router.get(
    "/submissions/{submission_id}/chat/conversations/{conversation_id}/messages",
    response_model=list[MessageResponse],
)
async def get_messages(
    submission_id: UUID,
    conversation_id: UUID,
    db: AsyncSession = Depends(get_db),
    _ai: None = Depends(require_ai_enabled),
) -> list[MessageResponse]:
    # Verify conversation belongs to submission
    result = await db.execute(
        select(Conversation).where(
            Conversation.id == conversation_id,
            Conversation.submission_id == submission_id,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Conversation not found")

    result = await db.execute(
        select(Message)
        .where(Message.conversation_id == conversation_id)
        .order_by(Message.created_at)
    )
    messages = result.scalars().all()
    return [MessageResponse.model_validate(m) for m in messages]


@router.post(
    "/submissions/{submission_id}/chat/conversations/{conversation_id}/messages",
)
async def send_message(
    submission_id: UUID,
    conversation_id: UUID,
    body: ChatMessageRequest,
    db: AsyncSession = Depends(get_db),
    llm: BaseLLMProvider = Depends(require_ai_enabled),
) -> StreamingResponse:
    submission = await _get_submission(db, submission_id)

    result = await db.execute(
        select(Conversation).where(
            Conversation.id == conversation_id,
            Conversation.submission_id == submission_id,
        )
    )
    conversation = result.scalar_one_or_none()
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")

    return StreamingResponse(
        send_message_stream(db, llm, submission, conversation, body.content),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
