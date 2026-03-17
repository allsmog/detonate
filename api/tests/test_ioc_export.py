import json
import uuid

import pytest


async def _submit(client):
    resp = await client.post(
        "/api/v1/submit",
        files={"file": (f"ioc_{uuid.uuid4().hex[:8]}.txt", b"ioc test content", "text/plain")},
    )
    return resp.json()


@pytest.mark.asyncio
async def test_extract_iocs(client):
    sub = await _submit(client)
    resp = await client.get(f"/api/v1/submissions/{sub['id']}/iocs")
    assert resp.status_code == 200
    data = resp.json()
    assert "hashes" in data
    assert data["hashes"]["sha256"] == sub["file_hash_sha256"]
    assert "ips" in data
    assert "domains" in data
    assert "file_paths" in data


@pytest.mark.asyncio
async def test_export_csv(client):
    sub = await _submit(client)
    resp = await client.get(f"/api/v1/submissions/{sub['id']}/iocs/csv")
    assert resp.status_code == 200
    content = resp.text
    assert "type,value" in content or "type" in content
    # Should contain the SHA256 hash
    assert sub["file_hash_sha256"] in content


@pytest.mark.asyncio
async def test_export_stix(client):
    sub = await _submit(client)
    resp = await client.get(f"/api/v1/submissions/{sub['id']}/iocs/stix")
    assert resp.status_code == 200
    data = resp.json()
    assert data["type"] == "bundle"
    assert "objects" in data
    assert len(data["objects"]) >= 1
    # Should have hash indicators
    patterns = [obj["pattern"] for obj in data["objects"]]
    assert any("SHA256" in p or "sha256" in p for p in patterns)


@pytest.mark.asyncio
async def test_export_json(client):
    sub = await _submit(client)
    resp = await client.get(f"/api/v1/submissions/{sub['id']}/iocs/json")
    assert resp.status_code == 200
    data = json.loads(resp.text)
    assert "hashes" in data


@pytest.mark.asyncio
async def test_ioc_not_found(client):
    fake_id = "00000000-0000-0000-0000-000000000000"
    resp = await client.get(f"/api/v1/submissions/{fake_id}/iocs")
    assert resp.status_code == 404
