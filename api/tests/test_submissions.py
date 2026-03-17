import pytest


@pytest.mark.asyncio
async def test_submit_file(client):
    response = await client.post(
        "/api/v1/submit",
        files={"file": ("test.txt", b"hello world", "text/plain")},
        data={"tags": "test,sample"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["filename"] == "test.txt"
    assert data["file_hash_sha256"] is not None
    assert data["file_hash_md5"] is not None
    assert data["file_hash_sha1"] is not None
    assert data["file_size"] == 11
    assert data["verdict"] == "unknown"
    assert data["score"] == 0
    assert "test" in data["tags"]
    assert "sample" in data["tags"]


@pytest.mark.asyncio
async def test_list_submissions(client):
    # Submit a file first
    await client.post(
        "/api/v1/submit",
        files={"file": ("list_test.txt", b"list test content", "text/plain")},
    )

    response = await client.get("/api/v1/submissions")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 1
    assert len(data["items"]) >= 1


@pytest.mark.asyncio
async def test_get_submission_by_id(client):
    # Submit a file first
    submit_response = await client.post(
        "/api/v1/submit",
        files={"file": ("get_test.txt", b"get test content", "text/plain")},
    )
    submission_id = submit_response.json()["id"]

    response = await client.get(f"/api/v1/submissions/{submission_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == submission_id
    assert data["filename"] == "get_test.txt"


@pytest.mark.asyncio
async def test_get_submission_not_found(client):
    response = await client.get(
        "/api/v1/submissions/00000000-0000-0000-0000-000000000000"
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_duplicate_file_dedup(client):
    content = b"dedup test content"

    # Submit same file twice
    resp1 = await client.post(
        "/api/v1/submit",
        files={"file": ("dedup1.txt", content, "text/plain")},
    )
    resp2 = await client.post(
        "/api/v1/submit",
        files={"file": ("dedup2.txt", content, "text/plain")},
    )

    assert resp1.status_code == 201
    assert resp2.status_code == 201

    data1 = resp1.json()
    data2 = resp2.json()

    # Different DB rows (different IDs)
    assert data1["id"] != data2["id"]
    # Same SHA256
    assert data1["file_hash_sha256"] == data2["file_hash_sha256"]
    # Same storage path (one MinIO object)
    assert data1["storage_path"] == data2["storage_path"]


@pytest.mark.asyncio
async def test_submit_via_submissions_endpoint(client):
    response = await client.post(
        "/api/v1/submissions",
        files={"file": ("alt.txt", b"alt endpoint", "text/plain")},
    )
    assert response.status_code == 201
