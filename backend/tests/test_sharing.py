import base64
import os

import pytest

pytestmark = pytest.mark.asyncio


def _b64(n: int = 16) -> str:
    return base64.b64encode(os.urandom(n)).decode()


async def register_and_login(client, key_bundle_fields, email, password="correct-horse-battery-staple"):
    register_resp = await client.post("/api/v1/auth/register", json={"email": email, "password": password, **key_bundle_fields})
    user_id = register_resp.json()["id"]
    login_resp = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    token = login_resp.json()["tokens"]["access_token"]
    return user_id, {"Authorization": f"Bearer {token}"}


def create_file_payload(num_chunks=1, chunk_size=1024, size_bytes=100):
    return {
        "encrypted_filename": _b64(32),
        "filename_nonce": _b64(12),
        "size_bytes": size_bytes,
        "chunk_size": chunk_size,
        "num_chunks": num_chunks,
        "ephemeral_public_key": _b64(32),
        "wrapped_key": _b64(48),
        "wrap_nonce": _b64(12),
    }


def share_payload(recipient_email):
    return {
        "recipient_email": recipient_email,
        "ephemeral_public_key": _b64(32),
        "wrapped_key": _b64(48),
        "wrap_nonce": _b64(12),
    }


async def _make_file_with_chunk(client, headers, content=b"alice's secret bytes"):
    resp = await client.post("/api/v1/files", json=create_file_payload(), headers=headers)
    file_id = resp.json()["id"]
    await client.put(
        f"/api/v1/files/{file_id}/chunks/0",
        content=content,
        headers={**headers, "X-Chunk-Nonce": _b64(12)},
    )
    return file_id


async def test_owner_can_share_and_recipient_gains_access(client, key_bundle_fields):
    _, alice = await register_and_login(client, key_bundle_fields, "alice@example.com")
    bob_id, bob = await register_and_login(client, key_bundle_fields, "bob@example.com")
    file_id = await _make_file_with_chunk(client, alice)

    resp = await client.post(f"/api/v1/files/{file_id}/shares", json=share_payload("bob@example.com"), headers=alice)
    assert resp.status_code == 201
    body = resp.json()
    assert body["recipient_email"] == "bob@example.com"
    assert body["permission"] == "read"

    resp = await client.get("/api/v1/files", headers=bob)
    files = resp.json()
    assert len(files) == 1
    assert files[0]["id"] == file_id
    assert files[0]["key_share"]["permission"] == "read"

    resp = await client.get(f"/api/v1/files/{file_id}/chunks/0", headers=bob)
    assert resp.status_code == 200
    assert resp.content == b"alice's secret bytes"


async def test_non_owner_cannot_share_file_with_others(client, key_bundle_fields):
    _, alice = await register_and_login(client, key_bundle_fields, "alice@example.com")
    _, bob = await register_and_login(client, key_bundle_fields, "bob@example.com")
    await register_and_login(client, key_bundle_fields, "carol@example.com")
    file_id = await _make_file_with_chunk(client, alice)

    await client.post(f"/api/v1/files/{file_id}/shares", json=share_payload("bob@example.com"), headers=alice)

    resp = await client.post(f"/api/v1/files/{file_id}/shares", json=share_payload("carol@example.com"), headers=bob)
    assert resp.status_code == 403


async def test_owner_can_revoke_and_recipient_loses_access(client, key_bundle_fields):
    _, alice = await register_and_login(client, key_bundle_fields, "alice@example.com")
    bob_id, bob = await register_and_login(client, key_bundle_fields, "bob@example.com")
    file_id = await _make_file_with_chunk(client, alice)
    await client.post(f"/api/v1/files/{file_id}/shares", json=share_payload("bob@example.com"), headers=alice)

    resp = await client.delete(f"/api/v1/files/{file_id}/shares/{bob_id}", headers=alice)
    assert resp.status_code == 204

    resp = await client.get("/api/v1/files", headers=bob)
    assert resp.json() == []

    resp = await client.get(f"/api/v1/files/{file_id}/chunks/0", headers=bob)
    assert resp.status_code == 404

    resp = await client.get(f"/api/v1/files/{file_id}/chunks/0", headers=alice)
    assert resp.status_code == 200


async def test_cannot_share_with_self(client, key_bundle_fields):
    _, alice = await register_and_login(client, key_bundle_fields, "alice@example.com")
    file_id = await _make_file_with_chunk(client, alice)

    resp = await client.post(f"/api/v1/files/{file_id}/shares", json=share_payload("alice@example.com"), headers=alice)
    assert resp.status_code == 400


async def test_cannot_share_with_nonexistent_user(client, key_bundle_fields):
    _, alice = await register_and_login(client, key_bundle_fields, "alice@example.com")
    file_id = await _make_file_with_chunk(client, alice)

    resp = await client.post(f"/api/v1/files/{file_id}/shares", json=share_payload("ghost@example.com"), headers=alice)
    assert resp.status_code == 404


async def test_cannot_share_twice_with_same_user(client, key_bundle_fields):
    _, alice = await register_and_login(client, key_bundle_fields, "alice@example.com")
    await register_and_login(client, key_bundle_fields, "bob@example.com")
    file_id = await _make_file_with_chunk(client, alice)

    await client.post(f"/api/v1/files/{file_id}/shares", json=share_payload("bob@example.com"), headers=alice)
    resp = await client.post(f"/api/v1/files/{file_id}/shares", json=share_payload("bob@example.com"), headers=alice)
    assert resp.status_code == 400


async def test_read_recipient_cannot_list_or_revoke_shares(client, key_bundle_fields):
    alice_id, alice = await register_and_login(client, key_bundle_fields, "alice@example.com")
    bob_id, bob = await register_and_login(client, key_bundle_fields, "bob@example.com")
    file_id = await _make_file_with_chunk(client, alice)
    await client.post(f"/api/v1/files/{file_id}/shares", json=share_payload("bob@example.com"), headers=alice)

    resp = await client.get(f"/api/v1/files/{file_id}/shares", headers=bob)
    assert resp.status_code == 403

    resp = await client.delete(f"/api/v1/files/{file_id}/shares/{alice_id}", headers=bob)
    assert resp.status_code == 403


async def test_user_with_no_access_gets_404_on_share_management(client, key_bundle_fields):
    _, alice = await register_and_login(client, key_bundle_fields, "alice@example.com")
    bob_id, bob = await register_and_login(client, key_bundle_fields, "bob@example.com")
    await register_and_login(client, key_bundle_fields, "carol@example.com")
    file_id = await _make_file_with_chunk(client, alice)

    resp = await client.get(f"/api/v1/files/{file_id}/shares", headers=bob)
    assert resp.status_code == 404

    resp = await client.post(f"/api/v1/files/{file_id}/shares", json=share_payload("carol@example.com"), headers=bob)
    assert resp.status_code == 404

    resp = await client.delete(f"/api/v1/files/{file_id}/shares/{bob_id}", headers=bob)
    assert resp.status_code == 404


async def test_cannot_revoke_owner_share(client, key_bundle_fields):
    alice_id, alice = await register_and_login(client, key_bundle_fields, "alice@example.com")
    file_id = await _make_file_with_chunk(client, alice)

    resp = await client.delete(f"/api/v1/files/{file_id}/shares/{alice_id}", headers=alice)
    assert resp.status_code == 400


async def test_shared_recipient_cannot_delete_or_upload_to_file(client, key_bundle_fields):
    _, alice = await register_and_login(client, key_bundle_fields, "alice@example.com")
    _, bob = await register_and_login(client, key_bundle_fields, "bob@example.com")
    file_id = await _make_file_with_chunk(client, alice)
    await client.post(f"/api/v1/files/{file_id}/shares", json=share_payload("bob@example.com"), headers=alice)

    resp = await client.delete(f"/api/v1/files/{file_id}", headers=bob)
    assert resp.status_code == 404

    resp = await client.put(
        f"/api/v1/files/{file_id}/chunks/0",
        content=b"overwrite attempt",
        headers={**bob, "X-Chunk-Nonce": _b64(12)},
    )
    assert resp.status_code == 404

    resp = await client.get(f"/api/v1/files/{file_id}/chunks/0", headers=alice)
    assert resp.content == b"alice's secret bytes"


async def test_list_shares_shows_owner_and_all_recipients(client, key_bundle_fields):
    _, alice = await register_and_login(client, key_bundle_fields, "alice@example.com")
    await register_and_login(client, key_bundle_fields, "bob@example.com")
    await register_and_login(client, key_bundle_fields, "carol@example.com")
    file_id = await _make_file_with_chunk(client, alice)

    await client.post(f"/api/v1/files/{file_id}/shares", json=share_payload("bob@example.com"), headers=alice)
    await client.post(f"/api/v1/files/{file_id}/shares", json=share_payload("carol@example.com"), headers=alice)

    resp = await client.get(f"/api/v1/files/{file_id}/shares", headers=alice)
    assert resp.status_code == 200
    shares = {s["recipient_email"]: s["permission"] for s in resp.json()}
    assert shares == {
        "alice@example.com": "owner",
        "bob@example.com": "read",
        "carol@example.com": "read",
    }
