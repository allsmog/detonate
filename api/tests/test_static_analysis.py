import uuid

import pytest


async def _submit(client, filename=None, content=b"static test"):
    fname = filename or f"static_{uuid.uuid4().hex[:8]}.txt"
    resp = await client.post(
        "/api/v1/submit",
        files={"file": (fname, content, "text/plain")},
    )
    return resp.json()


@pytest.mark.asyncio
async def test_static_analysis_text_file(client):
    sub = await _submit(client, content=b"hello world this is a test file with some strings")
    resp = await client.get(f"/api/v1/submissions/{sub['id']}/static")
    assert resp.status_code == 200
    data = resp.json()
    assert "entropy" in data
    assert "strings" in data
    assert data["entropy"]["overall"] > 0
    assert data["strings"]["total_ascii"] >= 0
    assert data["pe"] is None
    assert data["elf"] is None


@pytest.mark.asyncio
async def test_static_analysis_pe_file(client):
    """Submit the test PE binary and verify PE parsing."""
    import os
    pe_path = os.path.join(os.path.dirname(__file__), "fixtures", "test_sample.bin")
    if not os.path.exists(pe_path):
        pytest.skip("test PE sample not found")

    with open(pe_path, "rb") as f:
        pe_data = f.read()

    resp = await client.post(
        "/api/v1/submit",
        files={"file": ("test.exe", pe_data, "application/octet-stream")},
    )
    sub = resp.json()
    resp = await client.get(f"/api/v1/submissions/{sub['id']}/static")
    assert resp.status_code == 200
    data = resp.json()
    assert data["pe"] is not None
    pe = data["pe"]
    assert "sections" in pe
    assert "imports" in pe
    assert "entry_point" in pe
    assert isinstance(pe["sections"], list)


@pytest.mark.asyncio
async def test_strings_endpoint(client):
    content = b"http://evil.com/payload\nHKEY_LOCAL_MACHINE\\Software\\test\n" + b"A" * 100
    sub = await _submit(client, content=content)
    resp = await client.get(f"/api/v1/submissions/{sub['id']}/strings")
    assert resp.status_code == 200
    data = resp.json()
    assert "ascii_strings" in data or "items" in data


@pytest.mark.asyncio
async def test_pe_endpoint_non_pe(client):
    sub = await _submit(client, content=b"not a PE file")
    resp = await client.get(f"/api/v1/submissions/{sub['id']}/pe")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_entropy_range(client):
    sub = await _submit(client, content=b"aaaa" * 100)
    resp = await client.get(f"/api/v1/submissions/{sub['id']}/static")
    assert resp.status_code == 200
    entropy = resp.json()["entropy"]["overall"]
    assert 0 <= entropy <= 8.0
