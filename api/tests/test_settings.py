"""Tests for settings and feature flags endpoints.

Endpoints tested:
- GET /settings/features
- GET /ai/status
"""

import pytest


@pytest.mark.asyncio
async def test_feature_flags(client):
    """GET /settings/features returns all boolean flags."""
    resp = await client.get("/api/v1/settings/features")
    assert resp.status_code == 200
    data = resp.json()
    # All values should be booleans
    for key, value in data.items():
        assert isinstance(value, bool), f"Flag '{key}' should be bool, got {type(value)}"


@pytest.mark.asyncio
async def test_feature_flags_structure(client):
    """Verify all expected feature flags are present in the response."""
    resp = await client.get("/api/v1/settings/features")
    assert resp.status_code == 200
    data = resp.json()

    expected_flags = [
        "ai_enabled",
        "yara_enabled",
        "suricata_enabled",
        "auth_enabled",
        "screenshots_enabled",
        "qemu_enabled",
        "sandbox_pool_enabled",
    ]
    for flag in expected_flags:
        assert flag in data, f"Missing feature flag: {flag}"
        assert isinstance(data[flag], bool), f"Flag '{flag}' should be bool"


@pytest.mark.asyncio
async def test_feature_flags_no_auth_required(client):
    """GET /settings/features does not require authentication."""
    # The endpoint should be accessible without any Authorization header.
    # This is verified by the fact that the client fixture sends no auth
    # and we still get 200.
    resp = await client.get("/api/v1/settings/features")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_ai_status(client):
    """GET /ai/status returns enabled, configured, provider, model fields."""
    resp = await client.get("/api/v1/ai/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "enabled" in data
    assert isinstance(data["enabled"], bool)
    assert "configured" in data
    assert isinstance(data["configured"], bool)

    if data["enabled"]:
        # When AI is enabled, provider and model should be present
        assert "provider" in data
        assert data["provider"] is not None
        assert "model" in data
        assert data["model"] is not None
    else:
        # When AI is disabled, provider and model may be None
        assert "provider" in data
        assert "model" in data
