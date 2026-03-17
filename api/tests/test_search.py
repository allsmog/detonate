import uuid

import pytest


async def _submit(client, filename=None, content=b"search test", tags=""):
    fname = filename or f"search_{uuid.uuid4().hex[:8]}.txt"
    resp = await client.post(
        "/api/v1/submit",
        files={"file": (fname, content, "text/plain")},
        data={"tags": tags},
    )
    return resp.json()


@pytest.mark.asyncio
async def test_search_empty_query(client):
    await _submit(client)
    resp = await client.get("/api/v1/search")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 1


@pytest.mark.asyncio
async def test_search_by_filename(client):
    unique = uuid.uuid4().hex[:8]
    await _submit(client, filename=f"findme_{unique}.txt")
    resp = await client.get(f"/api/v1/search?q=findme_{unique}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert any(unique in item["filename"] for item in data["items"])


@pytest.mark.asyncio
async def test_search_by_hash(client):
    sub = await _submit(client, content=b"hash_search_unique_content_" + uuid.uuid4().bytes)
    sha = sub["file_hash_sha256"]
    resp = await client.get(f"/api/v1/search?q={sha[:16]}")
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1


@pytest.mark.asyncio
async def test_search_verdict_filter(client):
    await _submit(client)
    resp = await client.get("/api/v1/search?verdict=unknown")
    assert resp.status_code == 200
    for item in resp.json()["items"]:
        assert item["verdict"] == "unknown"


@pytest.mark.asyncio
async def test_search_tag_filter(client):
    tag = f"tag_{uuid.uuid4().hex[:6]}"
    await _submit(client, tags=tag)
    resp = await client.get(f"/api/v1/search?tag={tag}")
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1


@pytest.mark.asyncio
async def test_search_sort(client):
    await _submit(client)
    resp = await client.get("/api/v1/search?sort_by=score&sort_order=desc")
    assert resp.status_code == 200
    assert "items" in resp.json()


@pytest.mark.asyncio
async def test_search_pagination(client):
    for _ in range(3):
        await _submit(client)
    resp = await client.get("/api/v1/search?limit=2&offset=0")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) <= 2
    assert data["limit"] == 2
    assert data["offset"] == 0


@pytest.mark.asyncio
async def test_hash_lookup(client):
    sub = await _submit(client, content=b"lookup_" + uuid.uuid4().bytes)
    sha = sub["file_hash_sha256"]
    resp = await client.get(f"/api/v1/search/hash/{sha}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert any(item["file_hash_sha256"] == sha for item in data["items"])


@pytest.mark.asyncio
async def test_hash_lookup_not_found(client):
    resp = await client.get("/api/v1/search/hash/0000000000000000000000000000000000000000000000000000000000000000")
    assert resp.status_code == 200
    assert resp.json()["total"] == 0
