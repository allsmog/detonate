"""Tests for YARA scanning and rule management endpoints.

Endpoints tested:
- POST /submissions/{id}/yara (static YARA scan)
- GET /yara/rules (list rule files)
- POST /yara/rules/validate (validate YARA syntax)
- POST /yara/rules (upload new rule)
- DELETE /yara/rules/{filename} (delete rule)
"""

import uuid

import pytest


async def _submit(client, filename="yara_test.txt", content=b"yara test content"):
    resp = await client.post(
        "/api/v1/submit",
        files={"file": (filename, content, "text/plain")},
    )
    assert resp.status_code == 201
    return resp.json()


@pytest.mark.asyncio
async def test_yara_static_scan(client):
    """POST /submissions/{id}/yara scans a submitted file with YARA rules."""
    sub = await _submit(
        client,
        filename=f"yara_scan_{uuid.uuid4().hex[:8]}.txt",
        content=b"harmless test content for yara scanning",
    )
    submission_id = sub["id"]

    resp = await client.post(f"/api/v1/submissions/{submission_id}/yara")
    assert resp.status_code == 200
    data = resp.json()
    assert "matches" in data
    assert isinstance(data["matches"], list)
    assert "total_matches" in data
    assert data["total_matches"] == len(data["matches"])
    assert data["filename"] is not None
    assert data["file_hash"] is not None


@pytest.mark.asyncio
async def test_yara_list_rules(client):
    """GET /yara/rules returns a list of rule files with metadata."""
    resp = await client.get("/api/v1/yara/rules")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    # The sandbox ships with at least index.yar and a few rule files
    assert len(data) >= 1
    for rule_file in data:
        assert "filename" in rule_file
        assert rule_file["filename"].endswith(".yar")
        assert "rule_count" in rule_file
        assert "size_bytes" in rule_file
        assert "last_modified" in rule_file


@pytest.mark.asyncio
async def test_yara_validate_valid_rule(client):
    """POST /yara/rules/validate with valid YARA rule returns valid=true."""
    valid_rule = (
        'rule test_valid_rule {\n'
        '    strings:\n'
        '        $a = "test"\n'
        '    condition:\n'
        '        $a\n'
        '}'
    )
    resp = await client.post(
        "/api/v1/yara/rules/validate",
        json={"content": valid_rule},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["error"] is None


@pytest.mark.asyncio
async def test_yara_validate_invalid_rule(client):
    """POST /yara/rules/validate with syntax error returns valid=false."""
    invalid_rule = (
        'rule broken_rule {\n'
        '    strings:\n'
        '        $a = "test"\n'
        '    condition:\n'
        '        $a and and\n'  # syntax error: double 'and'
        '}'
    )
    resp = await client.post(
        "/api/v1/yara/rules/validate",
        json={"content": invalid_rule},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert data["error"] is not None
    assert len(data["error"]) > 0


@pytest.mark.asyncio
async def test_yara_upload_rule(client):
    """POST /yara/rules creates a new rule file."""
    unique_name = f"test_upload_{uuid.uuid4().hex[:8]}.yar"
    rule_content = (
        f'rule upload_test_{uuid.uuid4().hex[:8]} {{\n'
        '    strings:\n'
        '        $a = "upload_test_marker"\n'
        '    condition:\n'
        '        $a\n'
        '}'
    )
    resp = await client.post(
        "/api/v1/yara/rules",
        json={"filename": unique_name, "content": rule_content},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["filename"] == unique_name
    assert data["rule_count"] >= 1
    assert data["size_bytes"] > 0

    # Clean up: delete the uploaded rule
    del_resp = await client.delete(f"/api/v1/yara/rules/{unique_name}")
    assert del_resp.status_code == 204


@pytest.mark.asyncio
async def test_yara_delete_rule(client):
    """DELETE /yara/rules/{filename} removes the rule file."""
    # First create a rule to delete
    unique_name = f"test_delete_{uuid.uuid4().hex[:8]}.yar"
    rule_content = (
        f'rule delete_test_{uuid.uuid4().hex[:8]} {{\n'
        '    strings:\n'
        '        $a = "delete_test_marker"\n'
        '    condition:\n'
        '        $a\n'
        '}'
    )
    create_resp = await client.post(
        "/api/v1/yara/rules",
        json={"filename": unique_name, "content": rule_content},
    )
    assert create_resp.status_code == 201

    # Delete it
    del_resp = await client.delete(f"/api/v1/yara/rules/{unique_name}")
    assert del_resp.status_code == 204

    # Verify it's gone: GET should return 404
    get_resp = await client.get(f"/api/v1/yara/rules/{unique_name}")
    assert get_resp.status_code == 404


@pytest.mark.asyncio
async def test_yara_cannot_delete_index(client):
    """DELETE /yara/rules/index.yar returns 400 (protected file)."""
    resp = await client.delete("/api/v1/yara/rules/index.yar")
    assert resp.status_code == 400
    data = resp.json()
    assert "index" in data["detail"].lower()
