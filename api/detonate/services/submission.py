import hashlib

import magic
from fastapi import UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.config import settings
from detonate.models.submission import Submission
from detonate.services.storage import StorageService

CHUNK_SIZE = 65536  # 64KB


async def create_submission(
    file: UploadFile,
    tags: list[str] | None,
    db: AsyncSession,
    storage: StorageService,
) -> Submission:
    # Read file content in chunks for hashing
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    chunks: list[bytes] = []
    total_size = 0

    while True:
        chunk = await file.read(CHUNK_SIZE)
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > settings.max_file_size:
            raise ValueError(
                f"File exceeds maximum size of {settings.max_file_size} bytes"
            )
        sha256.update(chunk)
        md5.update(chunk)
        sha1.update(chunk)
        chunks.append(chunk)

    file_data = b"".join(chunks)
    sha256_hex = sha256.hexdigest()
    md5_hex = md5.hexdigest()
    sha1_hex = sha1.hexdigest()

    # Detect file type
    file_type = magic.from_buffer(file_data, mime=False)
    mime_type = magic.from_buffer(file_data, mime=True)

    # Upload to MinIO (dedup by SHA256)
    storage_path = f"samples/{sha256_hex}"
    if not storage.file_exists(storage_path):
        storage.upload_file(storage_path, file_data, content_type=mime_type)

    # Create DB record (each submission is a distinct event, even for same file)
    submission = Submission(
        filename=file.filename,
        file_hash_sha256=sha256_hex,
        file_hash_md5=md5_hex,
        file_hash_sha1=sha1_hex,
        file_size=total_size,
        file_type=file_type,
        mime_type=mime_type,
        storage_path=storage_path,
        tags=tags or [],
    )
    db.add(submission)
    await db.flush()
    await db.refresh(submission)
    return submission
