"""Tests for report generation and auto-tagging endpoints.

Endpoints tested:
- GET /submissions/{id}/report/html
- GET /submissions/{id}/report/download
- GET /submissions/{id}/report/iocs
- POST /submissions/{id}/auto-tag
"""

import uuid

import pytest


async def _submit(client, filename="report_test.txt", content=b"report test content"):
    resp = await client.post(
        "/api/v1/submit",
        files={"file": (filename, content, "text/plain")},
    )
    assert resp.status_code == 201
    return resp.json()


@pytest.mark.asyncio
async def test_html_report(client):
    """GET /submissions/{id}/report/html returns HTML content with proper headers."""
    sub = await _submit(client, filename=f"html_report_{uuid.uuid4().hex[:8]}.txt")
    submission_id = sub["id"]

    resp = await client.get(f"/api/v1/submissions/{submission_id}/report/html")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    body = resp.text
    assert "<html" in body.lower() or "<!doctype" in body.lower() or "<div" in body.lower()


@pytest.mark.asyncio
async def test_html_report_download(client):
    """GET /submissions/{id}/report/download returns Content-Disposition attachment."""
    sub = await _submit(client, filename=f"download_{uuid.uuid4().hex[:8]}.txt")
    submission_id = sub["id"]

    resp = await client.get(f"/api/v1/submissions/{submission_id}/report/download")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    cd = resp.headers.get("content-disposition", "")
    assert "attachment" in cd
    assert "filename=" in cd


@pytest.mark.asyncio
async def test_csv_ioc_report(client):
    """GET /submissions/{id}/report/iocs returns CSV content."""
    sub = await _submit(client, filename=f"csv_iocs_{uuid.uuid4().hex[:8]}.txt")
    submission_id = sub["id"]

    resp = await client.get(f"/api/v1/submissions/{submission_id}/report/iocs")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    cd = resp.headers.get("content-disposition", "")
    assert "attachment" in cd
    body = resp.text
    assert len(body) > 0


@pytest.mark.asyncio
async def test_auto_tag(client):
    """POST /submissions/{id}/auto-tag returns tags list with count."""
    sub = await _submit(client, filename=f"autotag_{uuid.uuid4().hex[:8]}.txt")
    submission_id = sub["id"]

    resp = await client.post(f"/api/v1/submissions/{submission_id}/auto-tag")
    assert resp.status_code == 200
    data = resp.json()
    assert "tags" in data
    assert "count" in data
    assert isinstance(data["tags"], list)
    assert data["count"] == len(data["tags"])
    assert data["submission_id"] == submission_id


@pytest.mark.asyncio
async def test_auto_tag_adds_type_tags(client):
    """Auto-tagging applies file type tags (e.g. 'text-file' for ASCII text)."""
    sub = await _submit(
        client,
        filename=f"typed_{uuid.uuid4().hex[:8]}.txt",
        content=b"This is plain ASCII text content for type detection.",
    )
    submission_id = sub["id"]

    resp = await client.post(f"/api/v1/submissions/{submission_id}/auto-tag")
    assert resp.status_code == 200
    data = resp.json()
    tags = data["tags"]
    assert isinstance(tags, list)
    has_type_tag = any(
        t in tags
        for t in ("text-file", "script", "html-file", "xml-file")
    )
    assert has_type_tag, f"Expected a file-type tag in {tags}"


@pytest.mark.asyncio
async def test_auto_tag_preserves_existing_tags(client):
    """Existing tags are not removed when auto-tagging is applied."""
    existing_tags = "custom-tag,manual-review"
    sub_resp = await client.post(
        "/api/v1/submit",
        files={
            "file": (
                f"preserve_{uuid.uuid4().hex[:8]}.txt",
                b"text content for preserve test",
                "text/plain",
            )
        },
        data={"tags": existing_tags},
    )
    assert sub_resp.status_code == 201
    sub = sub_resp.json()
    submission_id = sub["id"]
    assert "custom-tag" in sub["tags"]
    assert "manual-review" in sub["tags"]

    resp = await client.post(f"/api/v1/submissions/{submission_id}/auto-tag")
    assert resp.status_code == 200
    data = resp.json()
    tags = data["tags"]
    assert "custom-tag" in tags
    assert "manual-review" in tags


@pytest.mark.asyncio
async def test_report_not_found(client):
    """Report for nonexistent submission returns 404."""
    fake_id = "00000000-0000-0000-0000-000000000000"
    resp = await client.get(f"/api/v1/submissions/{fake_id}/report/html")
    assert resp.status_code == 404

    resp = await client.get(f"/api/v1/submissions/{fake_id}/report/download")
    assert resp.status_code == 404

    resp = await client.get(f"/api/v1/submissions/{fake_id}/report/iocs")
    assert resp.status_code == 404

    resp = await client.post(f"/api/v1/submissions/{fake_id}/auto-tag")
    assert resp.status_code == 404
