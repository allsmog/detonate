import hashlib
import logging
from urllib.parse import urlparse

import httpx
import magic
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.config import settings
from detonate.models.submission import Submission
from detonate.services.storage import StorageService

logger = logging.getLogger("detonate.services.url_submission")


async def submit_url(
    url: str,
    tags: list[str],
    db: AsyncSession,
    storage: StorageService,
    timeout: int = 30,
) -> Submission:
    """Download content from URL and create a submission."""
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
        response = await client.get(url)
        response.raise_for_status()

    content = response.content

    if len(content) > settings.max_file_size:
        raise ValueError(
            f"Downloaded file exceeds maximum size of {settings.max_file_size} bytes"
        )

    # Derive filename from URL or Content-Disposition
    filename = _extract_filename(url, response.headers)

    # Hash
    sha256 = hashlib.sha256(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()
    sha1 = hashlib.sha1(content).hexdigest()

    # Detect file type
    file_type = magic.from_buffer(content, mime=False)
    mime_type = magic.from_buffer(content, mime=True)

    # Store in MinIO (dedup by SHA256)
    storage_path = f"samples/{sha256}"
    if not storage.file_exists(storage_path):
        storage.upload_file(storage_path, content, content_type=mime_type)

    # Create submission
    submission = Submission(
        filename=filename,
        url=url,
        file_hash_sha256=sha256,
        file_hash_md5=md5,
        file_hash_sha1=sha1,
        file_size=len(content),
        file_type=file_type,
        mime_type=mime_type,
        storage_path=storage_path,
        tags=tags or [],
    )
    db.add(submission)
    await db.flush()
    await db.refresh(submission)

    logger.info(
        "URL submission created: %s -> %s (%s, %d bytes)",
        url,
        submission.id,
        sha256[:12],
        len(content),
    )
    return submission


def _extract_filename(url: str, headers: httpx.Headers) -> str:
    """Extract filename from Content-Disposition header or URL path."""
    # Check Content-Disposition first
    cd = headers.get("content-disposition", "")
    if "filename=" in cd:
        parts = cd.split("filename=")
        if len(parts) > 1:
            name = parts[1].strip().strip('"').strip("'").split(";")[0].strip()
            if name:
                return name

    # Fall back to URL path
    path = urlparse(url).path
    name = path.rsplit("/", 1)[-1] if "/" in path else path
    return name or "downloaded_file"
