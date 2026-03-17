"""Tests for threat intelligence endpoints.

Endpoints tested:
- GET /threat-intel/status
- GET /threat-intel/hash/{sha256}
"""

import uuid

import pytest


async def _submit(client, filename="ti_test.txt", content=b"threat intel test content"):
    resp = await client.post(
        "/api/v1/submit",
        files={"file": (filename, content, "text/plain")},
    )
    assert resp.status_code == 201
    return resp.json()


@pytest.mark.asyncio
async def test_threat_intel_status(client):
    """GET /threat-intel/status returns providers list."""
    resp = await client.get("/api/v1/threat-intel/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "providers" in data
    assert isinstance(data["providers"], list)
    assert len(data["providers"]) >= 1  # at least one provider is registered


@pytest.mark.asyncio
async def test_threat_intel_providers_structure(client):
    """Each provider in the status response has name and configured fields."""
    resp = await client.get("/api/v1/threat-intel/status")
    assert resp.status_code == 200
    data = resp.json()

    for provider in data["providers"]:
        assert "name" in provider, f"Provider missing 'name' field: {provider}"
        assert isinstance(provider["name"], str)
        assert len(provider["name"]) > 0

        assert "configured" in provider, f"Provider missing 'configured' field: {provider}"
        assert isinstance(provider["configured"], bool)


@pytest.mark.asyncio
async def test_threat_intel_known_providers(client):
    """The status endpoint should include well-known providers."""
    resp = await client.get("/api/v1/threat-intel/status")
    assert resp.status_code == 200
    data = resp.json()

    provider_names = [p["name"] for p in data["providers"]]
    # The service registers VirusTotal, AbuseIPDB, and OTX in get_status()
    assert any("virustotal" in name.lower() for name in provider_names), (
        f"Expected VirusTotal in providers, got {provider_names}"
    )


@pytest.mark.asyncio
async def test_threat_intel_hash_lookup(client):
    """GET /threat-intel/hash/{sha256} returns results (may be empty if no keys)."""
    # Use a well-known SHA256 (EICAR test file hash)
    eicar_sha256 = (
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    )

    resp = await client.get(f"/api/v1/threat-intel/hash/{eicar_sha256}")
    assert resp.status_code == 200
    data = resp.json()
    assert "sha256" in data
    assert data["sha256"] == eicar_sha256
    assert "results" in data
    assert isinstance(data["results"], list)
    # Each result should have the expected structure
    for result in data["results"]:
        assert "provider" in result
        assert "cached" in result
        # data may be None if provider is not configured
        assert "data" in result


@pytest.mark.asyncio
async def test_threat_intel_hash_lookup_for_submission(client):
    """Lookup a hash that was actually submitted to verify the flow."""
    sub = await _submit(
        client,
        filename=f"ti_hash_{uuid.uuid4().hex[:8]}.txt",
        content=f"unique threat intel test {uuid.uuid4().hex}".encode(),
    )
    sha256 = sub["file_hash_sha256"]

    resp = await client.get(f"/api/v1/threat-intel/hash/{sha256}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["sha256"] == sha256
    assert isinstance(data["results"], list)
