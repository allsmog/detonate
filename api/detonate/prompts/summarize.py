from detonate.models.submission import Submission


def build_summarize_prompt(submission: Submission) -> str:
    parts = [
        "Analyze the following file submission and provide a concise narrative summary.",
        "Focus on: what the file is, notable characteristics, and any potential concerns.",
        "",
        "## File Metadata",
        f"- Filename: {submission.filename or 'N/A'}",
        f"- SHA256: {submission.file_hash_sha256}",
        f"- MD5: {submission.file_hash_md5 or 'N/A'}",
        f"- SHA1: {submission.file_hash_sha1 or 'N/A'}",
        f"- File Size: {submission.file_size or 0} bytes",
        f"- File Type: {submission.file_type or 'N/A'}",
        f"- MIME Type: {submission.mime_type or 'N/A'}",
        f"- Tags: {', '.join(submission.tags) if submission.tags else 'None'}",
    ]
    return "\n".join(parts)
