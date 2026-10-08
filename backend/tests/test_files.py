import base64
import os

import pytest

from app.core.config import settings

pytestmark = pytest.mark.asyncio


def _b64(n: int = 16) -> str:
    return base64.b64encode(os.urandom(n)).decode()


async def register_and_login(client, key_bundle_fields, email="alice@example.com", password="correct-horse-battery-staple"):
    await client.post("/api/v1/auth/register", json={"email": email, "password": password, **key_bundle_fields})
    resp = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    token = resp.json()["tokens"]["access_token"]
    return {"Authorization": f"Bearer {token}"}


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


async def test_create_list_and_delete_file(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)

    resp = await client.post("/api/v1/files", json=create_file_payload(), headers=headers)
    assert resp.status_code == 201
    file_id = resp.json()["id"]

    resp = await client.get("/api/v1/files", headers=headers)
    assert resp.status_code == 200
    files = resp.json()
    assert len(files) == 1
    assert files[0]["id"] == file_id
    assert files[0]["key_share"]["permission"] == "owner"

    resp = await client.delete(f"/api/v1/files/{file_id}", headers=headers)
    assert resp.status_code == 204

    resp = await client.get("/api/v1/files", headers=headers)
    assert resp.json() == []


async def test_upload_and_download_chunk_round_trips(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)
    resp = await client.post("/api/v1/files", json=create_file_payload(num_chunks=1, chunk_size=1024), headers=headers)
    file_id = resp.json()["id"]

    ciphertext = os.urandom(64)
    nonce = os.urandom(12)
    resp = await client.put(
        f"/api/v1/files/{file_id}/chunks/0",
        content=ciphertext,
        headers={**headers, "Content-Type": "application/octet-stream", "X-Chunk-Nonce": base64.b64encode(nonce).decode()},
    )
    assert resp.status_code == 204

    resp = await client.get(f"/api/v1/files/{file_id}/chunks/0", headers=headers)
    assert resp.status_code == 200
    assert resp.content == ciphertext
    assert base64.b64decode(resp.headers["x-chunk-nonce"]) == nonce


async def test_upload_chunk_rejects_index_out_of_range(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)
    resp = await client.post("/api/v1/files", json=create_file_payload(num_chunks=1), headers=headers)
    file_id = resp.json()["id"]

    resp = await client.put(
        f"/api/v1/files/{file_id}/chunks/5",
        content=b"data",
        headers={**headers, "X-Chunk-Nonce": _b64(12)},
    )
    assert resp.status_code == 400


async def test_upload_chunk_rejects_oversized_chunk(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)
    resp = await client.post("/api/v1/files", json=create_file_payload(num_chunks=1, chunk_size=16, size_bytes=16), headers=headers)
    file_id = resp.json()["id"]

    resp = await client.put(
        f"/api/v1/files/{file_id}/chunks/0",
        content=os.urandom(1024),
        headers={**headers, "X-Chunk-Nonce": _b64(12)},
    )
    assert resp.status_code == 400


async def test_create_file_rejects_chunk_size_over_server_limit(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)
    payload = create_file_payload(chunk_size=settings.max_chunk_size_bytes + 1)
    resp = await client.post("/api/v1/files", json=payload, headers=headers)
    assert resp.status_code == 400


async def test_other_user_cannot_access_file_by_guessing_id(client, key_bundle_fields):
    alice_headers = await register_and_login(client, key_bundle_fields, email="alice@example.com")
    resp = await client.post("/api/v1/files", json=create_file_payload(num_chunks=1), headers=alice_headers)
    file_id = resp.json()["id"]
    await client.put(
        f"/api/v1/files/{file_id}/chunks/0",
        content=b"alice's secret bytes",
        headers={**alice_headers, "X-Chunk-Nonce": _b64(12)},
    )

    bob_headers = await register_and_login(client, key_bundle_fields, email="bob@example.com")

    resp = await client.get("/api/v1/files", headers=bob_headers)
    assert resp.json() == []

    resp = await client.get(f"/api/v1/files/{file_id}/chunks/0", headers=bob_headers)
    assert resp.status_code == 404

    resp = await client.delete(f"/api/v1/files/{file_id}", headers=bob_headers)
    assert resp.status_code == 404

    resp = await client.get(f"/api/v1/files/{file_id}/chunks/0", headers=alice_headers)
    assert resp.status_code == 200


async def test_cannot_upload_chunk_to_file_without_auth(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)
    resp = await client.post("/api/v1/files", json=create_file_payload(), headers=headers)
    file_id = resp.json()["id"]

    resp = await client.put(f"/api/v1/files/{file_id}/chunks/0", content=b"x", headers={"X-Chunk-Nonce": _b64(12)})
    assert resp.status_code == 401


async def test_create_file_rejects_num_chunks_inconsistent_with_size(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)
    resp = await client.post(
        "/api/v1/files", json=create_file_payload(num_chunks=1000, chunk_size=1024, size_bytes=100), headers=headers
    )
    assert resp.status_code == 400

    resp = await client.post(
        "/api/v1/files", json=create_file_payload(num_chunks=3, chunk_size=1024, size_bytes=2049), headers=headers
    )
    assert resp.status_code == 201


async def test_upload_chunk_rejects_more_bytes_than_its_share_of_declared_size(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)
    resp = await client.post(
        "/api/v1/files", json=create_file_payload(num_chunks=2, chunk_size=1024, size_bytes=1124), headers=headers
    )
    file_id = resp.json()["id"]
    put = lambda index, n: client.put(  # noqa: E731
        f"/api/v1/files/{file_id}/chunks/{index}", content=os.urandom(n), headers={**headers, "X-Chunk-Nonce": _b64(12)}
    )

    assert (await put(1, 116)).status_code == 204
    assert (await put(1, 117)).status_code == 400
    assert (await put(0, 1024 + 16)).status_code == 204


async def test_storage_quota_is_enforced_and_reported(client, key_bundle_fields, monkeypatch):
    monkeypatch.setattr(settings, "max_storage_bytes_per_user", 1000)
    headers = await register_and_login(client, key_bundle_fields)

    resp = await client.post("/api/v1/files", json=create_file_payload(size_bytes=600), headers=headers)
    assert resp.status_code == 201
    first_id = resp.json()["id"]

    resp = await client.get("/api/v1/users/me/storage", headers=headers)
    assert resp.json() == {"used_bytes": 600, "quota_bytes": 1000}

    resp = await client.post("/api/v1/files", json=create_file_payload(size_bytes=500), headers=headers)
    assert resp.status_code == 413

    await client.delete(f"/api/v1/files/{first_id}", headers=headers)
    resp = await client.post("/api/v1/files", json=create_file_payload(size_bytes=500), headers=headers)
    assert resp.status_code == 201


async def test_quota_counts_only_owned_files_not_shared_ones(client, key_bundle_fields, monkeypatch):
    monkeypatch.setattr(settings, "max_storage_bytes_per_user", 1000)
    alice = await register_and_login(client, key_bundle_fields)
    resp = await client.post("/api/v1/files", json=create_file_payload(size_bytes=900), headers=alice)
    file_id = resp.json()["id"]

    bob = await register_and_login(client, key_bundle_fields, email="bob@example.com")
    resp = await client.post(
        f"/api/v1/files/{file_id}/shares",
        json={"recipient_email": "bob@example.com", "ephemeral_public_key": _b64(32), "wrapped_key": _b64(48), "wrap_nonce": _b64(12)},
        headers=alice,
    )
    assert resp.status_code == 201

    resp = await client.get("/api/v1/users/me/storage", headers=bob)
    assert resp.json()["used_bytes"] == 0
