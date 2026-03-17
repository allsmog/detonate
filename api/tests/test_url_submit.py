"""Tests for URL submission endpoints.

Endpoints tested:
- POST /submit-url (download content from URL and create submission)

Note: test_submit_url uses a real HTTP request to httpbin.org.
If the external service is unavailable the test may fail with a 502/504.
"""

import uuid

import pytest


async def _submit(client, filename="url_test.txt", content=b"url test content"):
    resp = await client.post(
        "/api/v1/submit",
        files={"file": (filename, content, "text/plain")},
    )
    assert resp.status_code == 201
    return resp.json()


@pytest.mark.asyncio
async def test_submit_url(client):
    """POST /submit-url with a real small URL creates a submission."""
    resp = await client.post(
        "/api/v1/submit-url",
        json={
            "url": "https://httpbin.org/robots.txt",
            "tags": "url-test,automated",
        },
    )
    # 201 on success, but the external URL might be unavailable
    if resp.status_code == 201:
        data = resp.json()
        assert data["file_hash_sha256"] is not None
        assert data["file_size"] is not None
        assert data["file_size"] > 0
        assert data["url"] == "https://httpbin.org/robots.txt"
        assert "url-test" in data["tags"]
        assert "automated" in data["tags"]
        assert data["filename"] is not None
    else:
        # External service may be down; accept 502 or 504
        assert resp.status_code in (502, 504), (
            f"Unexpected status {resp.status_code}: {resp.text}"
        )


@pytest.mark.asyncio
async def test_submit_url_invalid(client):
    """POST /submit-url with an unreachable URL returns an error."""
    resp = await client.post(
        "/api/v1/submit-url",
        json={
            "url": "https://this-domain-does-not-exist-xyz123.invalid/file.bin",
        },
    )
    # Should fail with 502 (connection error) or similar
    assert resp.status_code in (502, 504)


@pytest.mark.asyncio
async def test_submit_url_creates_submission(client):
    """Verify the submission from URL submit is retrievable via GET."""
    resp = await client.post(
        "/api/v1/submit-url",
        json={
            "url": "https://httpbin.org/robots.txt",
            "tags": f"retrieve-test-{uuid.uuid4().hex[:8]}",
        },
    )
    if resp.status_code != 201:
        pytest.skip("External URL httpbin.org is not reachable")

    data = resp.json()
    submission_id = data["id"]

    # Retrieve the submission by ID
    get_resp = await client.get(f"/api/v1/submissions/{submission_id}")
    assert get_resp.status_code == 200
    get_data = get_resp.json()
    assert get_data["id"] == submission_id
    assert get_data["url"] == "https://httpbin.org/robots.txt"
    assert get_data["file_hash_sha256"] == data["file_hash_sha256"]


@pytest.mark.asyncio
async def test_submit_url_missing_url_field(client):
    """POST /submit-url without the required 'url' field returns 422."""
    resp = await client.post(
        "/api/v1/submit-url",
        json={"tags": "missing-url"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_submit_url_empty_body(client):
    """POST /submit-url with empty body returns 422."""
    resp = await client.post(
        "/api/v1/submit-url",
        json={},
    )
    assert resp.status_code == 422
