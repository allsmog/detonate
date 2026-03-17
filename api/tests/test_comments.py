"""Tests for collaboration features (comments).

Endpoints tested:
- GET /submissions/{id}/comments
- POST /submissions/{id}/comments (requires auth)

Note: Comments require authentication (get_current_user dependency).
When auth_enabled=False (default), the bearer scheme still requires a
valid JWT or API key to identify the user. Tests that need auth will
register a user and obtain a JWT token.
"""

import uuid

import pytest


async def _submit(client, filename="comment_test.txt", content=b"comment test content"):
    resp = await client.post(
        "/api/v1/submit",
        files={"file": (filename, content, "text/plain")},
    )
    assert resp.status_code == 201
    return resp.json()


async def _register_and_login(client, email=None, password="testpassword123"):
    """Register a new user and return the JWT access token."""
    if email is None:
        email = f"comment_user_{uuid.uuid4().hex[:8]}@test.local"
    reg_resp = await client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": password,
            "display_name": "Test User",
        },
    )
    assert reg_resp.status_code == 201

    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login_resp.status_code == 200
    return login_resp.json()["access_token"]


@pytest.mark.asyncio
async def test_list_comments_empty(client):
    """GET /submissions/{id}/comments returns empty list for new submission."""
    sub = await _submit(
        client,
        filename=f"no_comments_{uuid.uuid4().hex[:8]}.txt",
    )
    submission_id = sub["id"]

    resp = await client.get(f"/api/v1/submissions/{submission_id}/comments")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert data["items"] == []
    assert data["total"] == 0


@pytest.mark.asyncio
async def test_add_comment_requires_auth(client):
    """POST comment without auth returns 401 (comments always require auth)."""
    sub = await _submit(
        client,
        filename=f"auth_comment_{uuid.uuid4().hex[:8]}.txt",
    )
    submission_id = sub["id"]

    # No Authorization header -- should fail with 401
    resp = await client.post(
        f"/api/v1/submissions/{submission_id}/comments",
        json={"content": "This comment should fail without auth"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_add_comment_with_auth(client):
    """POST comment with valid auth creates a comment successfully."""
    token = await _register_and_login(client)
    sub = await _submit(
        client,
        filename=f"auth_ok_comment_{uuid.uuid4().hex[:8]}.txt",
    )
    submission_id = sub["id"]

    comment_content = f"Test comment {uuid.uuid4().hex[:8]}"
    resp = await client.post(
        f"/api/v1/submissions/{submission_id}/comments",
        json={"content": comment_content},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["content"] == comment_content
    assert data["submission_id"] == submission_id
    assert "user_email" in data
    assert "created_at" in data


@pytest.mark.asyncio
async def test_list_comments_after_adding(client):
    """After adding a comment, the list endpoint returns it."""
    token = await _register_and_login(client)
    sub = await _submit(
        client,
        filename=f"list_after_add_{uuid.uuid4().hex[:8]}.txt",
    )
    submission_id = sub["id"]

    comment_content = f"Visible comment {uuid.uuid4().hex[:8]}"
    create_resp = await client.post(
        f"/api/v1/submissions/{submission_id}/comments",
        json={"content": comment_content},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert create_resp.status_code == 201

    list_resp = await client.get(f"/api/v1/submissions/{submission_id}/comments")
    assert list_resp.status_code == 200
    data = list_resp.json()
    assert data["total"] >= 1
    found = any(c["content"] == comment_content for c in data["items"])
    assert found, "The newly added comment should appear in the list"


@pytest.mark.asyncio
async def test_comments_not_found_submission(client):
    """GET comments for nonexistent submission returns 404."""
    fake_id = "00000000-0000-0000-0000-000000000000"
    resp = await client.get(f"/api/v1/submissions/{fake_id}/comments")
    assert resp.status_code == 404
