import uuid

import pytest


async def _submit(client):
    resp = await client.post(
        "/api/v1/submit",
        files={"file": (f"dash_{uuid.uuid4().hex[:8]}.txt", b"dashboard test", "text/plain")},
    )
    return resp.json()


@pytest.mark.asyncio
async def test_dashboard_stats(client):
    resp = await client.get("/api/v1/dashboard/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_submissions" in data
    assert "total_analyses" in data
    assert "verdicts" in data
    assert "average_score" in data
    assert "top_file_types" in data
    assert "top_tags" in data
    assert "analysis_status_breakdown" in data


@pytest.mark.asyncio
async def test_dashboard_stats_after_submission(client):
    before = (await client.get("/api/v1/dashboard/stats")).json()
    await _submit(client)
    after = (await client.get("/api/v1/dashboard/stats")).json()
    assert after["total_submissions"] >= before["total_submissions"] + 1


@pytest.mark.asyncio
async def test_dashboard_timeline(client):
    await _submit(client)
    resp = await client.get("/api/v1/dashboard/timeline")
    assert resp.status_code == 200
    data = resp.json()
    assert "points" in data
    assert isinstance(data["points"], list)


@pytest.mark.asyncio
async def test_dashboard_timeline_days(client):
    resp = await client.get("/api/v1/dashboard/timeline?days=7")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["points"]) <= 8  # at most 7 days + today


@pytest.mark.asyncio
async def test_dashboard_top_iocs(client):
    resp = await client.get("/api/v1/dashboard/top-iocs")
    assert resp.status_code == 200
    data = resp.json()
    assert "ips" in data
    assert "domains" in data
    assert isinstance(data["ips"], list)
    assert isinstance(data["domains"], list)
