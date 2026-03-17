"""Tests for team management endpoints.

Endpoints tested:
- GET /teams (requires auth)
- POST /teams (requires auth)
- GET /teams/{id} (requires auth)

Note: All team endpoints use Depends(get_current_user) which requires
authentication. Tests register a user and use a JWT token.
"""

import uuid

import pytest


async def _register_and_login(client, email=None, password="testpassword123"):
    """Register a new user and return the JWT access token."""
    if email is None:
        email = f"team_user_{uuid.uuid4().hex[:8]}@test.local"
    reg_resp = await client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": password,
            "display_name": "Team Test User",
        },
    )
    assert reg_resp.status_code == 201

    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login_resp.status_code == 200
    return login_resp.json()["access_token"]


@pytest.mark.asyncio
async def test_list_teams_requires_auth(client):
    """GET /teams without auth returns 401."""
    resp = await client.get("/api/v1/teams")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_teams(client):
    """GET /teams returns list of teams for authenticated user."""
    token = await _register_and_login(client)

    resp = await client.get(
        "/api/v1/teams",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert isinstance(data["items"], list)


@pytest.mark.asyncio
async def test_create_team(client):
    """POST /teams creates a new team and returns it."""
    token = await _register_and_login(client)

    team_name = f"Test Team {uuid.uuid4().hex[:8]}"
    resp = await client.post(
        "/api/v1/teams",
        json={"name": team_name, "description": "A team for testing"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == team_name
    assert data["description"] == "A team for testing"
    assert data["is_active"] is True
    assert data["member_count"] == 1  # creator is the first member
    assert "id" in data
    assert "created_at" in data


@pytest.mark.asyncio
async def test_get_team_detail(client):
    """GET /teams/{id} returns team detail with members."""
    token = await _register_and_login(client)

    team_name = f"Detail Team {uuid.uuid4().hex[:8]}"
    create_resp = await client.post(
        "/api/v1/teams",
        json={"name": team_name, "description": "Detail test team"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert create_resp.status_code == 201
    team_id = create_resp.json()["id"]

    resp = await client.get(
        f"/api/v1/teams/{team_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == team_id
    assert data["name"] == team_name
    assert "members" in data
    assert len(data["members"]) == 1
    # The creator should be the owner
    assert data["members"][0]["role"] == "owner"


@pytest.mark.asyncio
async def test_created_team_appears_in_list(client):
    """After creating a team, it appears in the team list."""
    token = await _register_and_login(client)

    team_name = f"Listed Team {uuid.uuid4().hex[:8]}"
    create_resp = await client.post(
        "/api/v1/teams",
        json={"name": team_name},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert create_resp.status_code == 201
    team_id = create_resp.json()["id"]

    list_resp = await client.get(
        "/api/v1/teams",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert list_resp.status_code == 200
    data = list_resp.json()
    team_ids = [t["id"] for t in data["items"]]
    assert team_id in team_ids
