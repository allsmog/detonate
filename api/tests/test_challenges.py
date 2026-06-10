"""Tests for the CTF challenge feature.

Uses a local client fixture (Postgres-backed) that stubs object storage, since
the challenge endpoints never touch MinIO/S3.
"""

import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from detonate.config import settings
from detonate.services.challenge import hash_flag, normalize_flag, verify_flag


@pytest.fixture
async def client():
    test_engine = create_async_engine(settings.database_url, echo=False)
    test_session_factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )

    async def override_get_db():
        async with test_session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    # Build the app and override DB + storage (challenges don't use storage).
    from detonate.api.deps import get_db, get_storage
    from detonate.main import create_app

    _app = create_app()
    _app.dependency_overrides[get_db] = override_get_db

    class _StubStorage:
        def ensure_bucket(self):
            return None

    _app.dependency_overrides[get_storage] = lambda: _StubStorage()

    transport = ASGITransport(app=_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    await test_engine.dispose()


# ---- unit tests (no DB) ----------------------------------------------------

def test_hash_flag_is_stable_and_normalized():
    assert hash_flag("FLAG{x}") == hash_flag("  FLAG{x}  ")
    assert normalize_flag("  a ") == "a"
    assert len(hash_flag("anything")) == 64  # sha256 hex


def test_verify_flag():
    class C:
        flag_hash = hash_flag("CAPSTONE-01")

    assert verify_flag(C(), "CAPSTONE-01") is True
    assert verify_flag(C(), " CAPSTONE-01 ") is True  # whitespace tolerant
    assert verify_flag(C(), "capstone-01") is False  # case sensitive
    assert verify_flag(C(), "wrong") is False


# ---- API tests (Postgres) --------------------------------------------------

@pytest.mark.asyncio
async def test_list_seeds_challenges(client):
    resp = await client.get("/api/v1/challenges")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] >= 5
    slugs = {c["slug"] for c in body["challenges"]}
    assert {"crackme-flag", "unpack-the-stub", "extract-the-config", "capstone-botid"} <= slugs
    # Flags/hashes must never be exposed
    assert "flag" not in body["challenges"][0]
    assert "flag_hash" not in body["challenges"][0]
    assert body["total_points"] > 0


@pytest.mark.asyncio
async def test_get_single_challenge(client):
    resp = await client.get("/api/v1/challenges/crackme-flag")
    assert resp.status_code == 200
    c = resp.json()
    assert c["slug"] == "crackme-flag"
    assert c["points"] == 100
    assert len(c["hints"]) >= 1
    assert c["module_ref"].startswith("masterclass/")


@pytest.mark.asyncio
async def test_get_unknown_challenge_404(client):
    resp = await client.get("/api/v1/challenges/does-not-exist")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_wrong_flag_rejected(client):
    resp = await client.post(
        "/api/v1/challenges/capstone-botid/submit",
        json={"flag": "NOPE", "player": f"tester-wrong-{uuid.uuid4().hex[:8]}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["correct"] is False
    assert body["points_awarded"] == 0


@pytest.mark.asyncio
async def test_correct_flag_awards_points_once(client):
    player = f"tester-correct-{uuid.uuid4().hex[:8]}"
    # First correct submission -> first_solve + points
    r1 = await client.post(
        "/api/v1/challenges/capstone-botid/submit",
        json={"flag": "CAPSTONE-01", "player": player},
    )
    assert r1.status_code == 200
    b1 = r1.json()
    assert b1["correct"] is True
    assert b1["first_solve"] is True
    assert b1["points_awarded"] == 500

    # Duplicate correct submission -> no extra points
    r2 = await client.post(
        "/api/v1/challenges/capstone-botid/submit",
        json={"flag": "CAPSTONE-01", "player": player},
    )
    b2 = r2.json()
    assert b2["correct"] is True
    assert b2["first_solve"] is False
    assert b2["points_awarded"] == 0

    # The challenge now shows as solved for this player
    resp = await client.get(f"/api/v1/challenges/capstone-botid?player={player}")
    assert resp.json()["solved"] is True


@pytest.mark.asyncio
async def test_leaderboard_reflects_solves(client):
    player = f"leader-{uuid.uuid4().hex[:8]}"
    await client.post(
        "/api/v1/challenges/deobfuscate-c2/submit",
        json={"flag": "c2.example.com", "player": player},
    )
    resp = await client.get("/api/v1/challenges/leaderboard")
    assert resp.status_code == 200
    entries = resp.json()["entries"]
    me = [e for e in entries if e["player"] == player]
    assert me and me[0]["points"] >= 150
