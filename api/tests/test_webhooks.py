"""Tests for webhook management endpoints.

Endpoints tested:
- GET /webhooks
- POST /webhooks
- DELETE /webhooks/{id}

Note: When auth_enabled=False (default), webhook endpoints work without
authentication. The user_id will be None, so webhooks are treated as
"global" webhooks. The _require_auth_or_pass helper allows unauthenticated
access when auth is disabled.
"""

import uuid

import pytest


@pytest.mark.asyncio
async def test_list_webhooks_empty(client):
    """GET /webhooks returns empty list when no webhooks exist for the user."""
    resp = await client.get("/api/v1/webhooks")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    # May not be empty if other tests created global webhooks,
    # but the response structure should be a list of webhook objects


@pytest.mark.asyncio
async def test_create_webhook(client):
    """POST /webhooks creates a webhook and returns it."""
    unique_url = f"https://example.com/webhook/{uuid.uuid4().hex[:8]}"
    resp = await client.post(
        "/api/v1/webhooks",
        json={
            "url": unique_url,
            "events": ["submission.created", "analysis.completed"],
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["url"] == unique_url
    assert "submission.created" in data["events"]
    assert "analysis.completed" in data["events"]
    assert data["is_active"] is True
    assert "id" in data
    assert data["failure_count"] == 0


@pytest.mark.asyncio
async def test_create_webhook_with_secret(client):
    """POST /webhooks with a signing secret creates the webhook."""
    unique_url = f"https://example.com/signed/{uuid.uuid4().hex[:8]}"
    resp = await client.post(
        "/api/v1/webhooks",
        json={
            "url": unique_url,
            "events": ["webhook.test"],
            "secret": "my-hmac-secret-123",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["url"] == unique_url
    assert "webhook.test" in data["events"]


@pytest.mark.asyncio
async def test_create_webhook_invalid_event(client):
    """POST /webhooks with an invalid event name returns 422."""
    resp = await client.post(
        "/api/v1/webhooks",
        json={
            "url": "https://example.com/invalid-event",
            "events": ["invalid.event.name"],
        },
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_delete_webhook(client):
    """DELETE /webhooks/{id} removes the webhook."""
    # Create a webhook first
    unique_url = f"https://example.com/delete/{uuid.uuid4().hex[:8]}"
    create_resp = await client.post(
        "/api/v1/webhooks",
        json={
            "url": unique_url,
            "events": ["submission.created"],
        },
    )
    assert create_resp.status_code == 201
    webhook_id = create_resp.json()["id"]

    # Delete it
    del_resp = await client.delete(f"/api/v1/webhooks/{webhook_id}")
    assert del_resp.status_code == 204

    # Verify it no longer appears in the list
    list_resp = await client.get("/api/v1/webhooks")
    assert list_resp.status_code == 200
    webhook_ids = [wh["id"] for wh in list_resp.json()]
    assert webhook_id not in webhook_ids


@pytest.mark.asyncio
async def test_delete_webhook_not_found(client):
    """DELETE /webhooks/{id} for nonexistent webhook returns 404."""
    fake_id = "00000000-0000-0000-0000-000000000000"
    resp = await client.delete(f"/api/v1/webhooks/{fake_id}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_created_webhook_appears_in_list(client):
    """After creating a webhook, it appears in the list."""
    unique_url = f"https://example.com/listed/{uuid.uuid4().hex[:8]}"
    create_resp = await client.post(
        "/api/v1/webhooks",
        json={
            "url": unique_url,
            "events": ["analysis.completed"],
        },
    )
    assert create_resp.status_code == 201
    webhook_id = create_resp.json()["id"]

    list_resp = await client.get("/api/v1/webhooks")
    assert list_resp.status_code == 200
    webhook_ids = [wh["id"] for wh in list_resp.json()]
    assert webhook_id in webhook_ids
