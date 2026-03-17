import uuid

import pytest


def _unique_email():
    return f"test_{uuid.uuid4().hex[:8]}@example.com"


@pytest.mark.asyncio
async def test_register_user(client):
    email = _unique_email()
    resp = await client.post("/api/v1/auth/register", json={
        "email": email, "password": "securepass123", "display_name": "Test User"
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == email
    assert data["display_name"] == "Test User"
    assert data["role"] == "user"
    assert "id" in data


@pytest.mark.asyncio
async def test_register_duplicate_email(client):
    email = _unique_email()
    await client.post("/api/v1/auth/register", json={
        "email": email, "password": "securepass123"
    })
    resp = await client.post("/api/v1/auth/register", json={
        "email": email, "password": "securepass123"
    })
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_register_short_password(client):
    resp = await client.post("/api/v1/auth/register", json={
        "email": _unique_email(), "password": "short"
    })
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_login_success(client):
    email = _unique_email()
    await client.post("/api/v1/auth/register", json={
        "email": email, "password": "securepass123"
    })
    resp = await client.post("/api/v1/auth/login", json={
        "email": email, "password": "securepass123"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == email


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    email = _unique_email()
    await client.post("/api/v1/auth/register", json={
        "email": email, "password": "securepass123"
    })
    resp = await client.post("/api/v1/auth/login", json={
        "email": email, "password": "wrongpassword"
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_nonexistent(client):
    resp = await client.post("/api/v1/auth/login", json={
        "email": "nobody@example.com", "password": "securepass123"
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_me(client):
    email = _unique_email()
    await client.post("/api/v1/auth/register", json={
        "email": email, "password": "securepass123"
    })
    login = await client.post("/api/v1/auth/login", json={
        "email": email, "password": "securepass123"
    })
    token = login.json()["access_token"]
    resp = await client.get("/api/v1/auth/me", headers={
        "Authorization": f"Bearer {token}"
    })
    assert resp.status_code == 200
    assert resp.json()["email"] == email


@pytest.mark.asyncio
async def test_get_me_no_token(client):
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_create_api_key(client):
    email = _unique_email()
    await client.post("/api/v1/auth/register", json={
        "email": email, "password": "securepass123"
    })
    login = await client.post("/api/v1/auth/login", json={
        "email": email, "password": "securepass123"
    })
    token = login.json()["access_token"]
    resp = await client.post("/api/v1/auth/api-keys", json={
        "name": "CI Key"
    }, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code in (200, 201)
    data = resp.json()
    assert "key" in data
    assert data["api_key"]["name"] == "CI Key"
    assert len(data["api_key"]["key_prefix"]) == 8


@pytest.mark.asyncio
async def test_list_api_keys(client):
    email = _unique_email()
    await client.post("/api/v1/auth/register", json={
        "email": email, "password": "securepass123"
    })
    login = await client.post("/api/v1/auth/login", json={
        "email": email, "password": "securepass123"
    })
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    await client.post("/api/v1/auth/api-keys", json={"name": "K1"}, headers=headers)
    resp = await client.get("/api/v1/auth/api-keys", headers=headers)
    assert resp.status_code == 200
    assert len(resp.json()) >= 1
