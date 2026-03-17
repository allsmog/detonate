from detonate.models.submission import Submission


def build_classify_prompt(submission: Submission) -> str:
    parts = [
        "Classify the following file submission. Return ONLY a JSON object with these fields:",
        '- "verdict": one of "clean", "suspicious", "malicious", "unknown"',
        '- "score": integer 0-100 (0=certainly clean, 100=certainly malicious)',
        '- "confidence": one of "low", "medium", "high"',
        '- "reasoning": brief explanation of your classification',
        "",
        "## File Metadata",
        f"- Filename: {submission.filename or 'N/A'}",
        f"- SHA256: {submission.file_hash_sha256}",
        f"- MD5: {submission.file_hash_md5 or 'N/A'}",
        f"- File Size: {submission.file_size or 0} bytes",
        f"- File Type: {submission.file_type or 'N/A'}",
        f"- MIME Type: {submission.mime_type or 'N/A'}",
        f"- Tags: {', '.join(submission.tags) if submission.tags else 'None'}",
        "",
        "Respond with ONLY the JSON object, no markdown fences or extra text.",
    ]
    return "\n".join(parts)
