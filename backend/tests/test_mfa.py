import base64
import os

import pyotp
import pytest

pytestmark = pytest.mark.asyncio


def _b64(n: int = 16) -> str:
    return base64.b64encode(os.urandom(n)).decode()


async def register_and_login(client, key_bundle_fields, email="alice@example.com", password="correct-horse-battery-staple"):
    await client.post("/api/v1/auth/register", json={"email": email, "password": password, **key_bundle_fields})
    resp = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.json().get("mfa_required") is not True
    token = resp.json()["tokens"]["access_token"]
    return {"Authorization": f"Bearer {token}"}


async def refresh_headers(client, headers):
    resp = await client.post("/api/v1/auth/refresh")
    assert resp.status_code == 200
    headers["Authorization"] = f"Bearer {resp.json()['access_token']}"


async def enable_totp(client, headers):
    setup = await client.post("/api/v1/auth/totp/setup", headers=headers)
    secret = setup.json()["secret"]
    code = pyotp.TOTP(secret).now()
    verify = await client.post("/api/v1/auth/totp/verify", json={"code": code}, headers=headers)
    assert verify.status_code == 204
    await refresh_headers(client, headers)
    return secret


async def test_totp_setup_returns_secret_uri_and_qr(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)

    resp = await client.post("/api/v1/auth/totp/setup", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["secret"]) >= 16
    assert body["otpauth_uri"].startswith("otpauth://totp/")
    assert body["qr_code_data_uri"].startswith("data:image/png;base64,")


async def test_totp_setup_requires_auth(client, key_bundle_fields):
    resp = await client.post("/api/v1/auth/totp/setup")
    assert resp.status_code == 401


async def test_totp_verify_rejects_wrong_code(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)
    await client.post("/api/v1/auth/totp/setup", headers=headers)

    resp = await client.post("/api/v1/auth/totp/verify", json={"code": "000000"}, headers=headers)
    assert resp.status_code == 400


async def test_totp_verify_enables_mfa_required_at_next_login(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)
    secret = await enable_totp(client, headers)

    resp = await client.post(
        "/api/v1/auth/login", json={"email": "alice@example.com", "password": "correct-horse-battery-staple"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["mfa_required"] is True
    assert body["methods"] == ["totp"]
    assert "tokens" not in body or body["tokens"] is None
    mfa_token = body["mfa_token"]

    resp = await client.post(
        "/api/v1/auth/login/mfa/totp", json={"mfa_token": mfa_token, "code": pyotp.TOTP(secret).now()}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["tokens"]["access_token"]
    assert body["key_bundle"]["public_key"]


async def test_login_mfa_totp_rejects_wrong_code(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)
    await enable_totp(client, headers)

    login_resp = await client.post(
        "/api/v1/auth/login", json={"email": "alice@example.com", "password": "correct-horse-battery-staple"}
    )
    mfa_token = login_resp.json()["mfa_token"]

    resp = await client.post("/api/v1/auth/login/mfa/totp", json={"mfa_token": mfa_token, "code": "000000"})
    assert resp.status_code == 401


async def test_login_mfa_totp_rejects_invalid_mfa_token(client, key_bundle_fields):
    resp = await client.post("/api/v1/auth/login/mfa/totp", json={"mfa_token": "garbage", "code": "123456"})
    assert resp.status_code == 401


async def test_totp_disable_requires_correct_password(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)
    await enable_totp(client, headers)

    resp = await client.post("/api/v1/auth/totp/disable", json={"password": "wrong-password"}, headers=headers)
    assert resp.status_code == 401

    resp = await client.post(
        "/api/v1/auth/totp/disable", json={"password": "correct-horse-battery-staple"}, headers=headers
    )
    assert resp.status_code == 204

    resp = await client.post(
        "/api/v1/auth/login", json={"email": "alice@example.com", "password": "correct-horse-battery-staple"}
    )
    assert resp.json().get("mfa_required") is not True
    assert resp.json()["tokens"]["access_token"]


async def test_mfa_status_reflects_totp_state(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)

    resp = await client.get("/api/v1/users/me/mfa-status", headers=headers)
    assert resp.json() == {"totp_enabled": False, "webauthn_credential_count": 0}

    await enable_totp(client, headers)

    resp = await client.get("/api/v1/users/me/mfa-status", headers=headers)
    assert resp.json() == {"totp_enabled": True, "webauthn_credential_count": 0}


async def test_enabling_totp_revokes_earlier_tokens_but_keeps_this_session(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)
    stale_headers = dict(headers)
    stale_refresh = client.cookies.get("cv_refresh")

    await enable_totp(client, headers)

    resp = await client.get("/api/v1/users/me/mfa-status", headers=stale_headers)
    assert resp.status_code == 401
    current_refresh = client.cookies.get("cv_refresh")
    client.cookies.clear()
    client.cookies.set("cv_refresh", stale_refresh, domain="test.local", path="/api/v1/auth")
    assert (await client.post("/api/v1/auth/refresh")).status_code == 401

    client.cookies.clear()
    client.cookies.set("cv_refresh", current_refresh, domain="test.local", path="/api/v1/auth")
    assert (await client.post("/api/v1/auth/refresh")).status_code == 200
    resp = await client.get("/api/v1/users/me/mfa-status", headers=headers)
    assert resp.status_code == 200


async def test_disabling_totp_revokes_earlier_tokens(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)
    await enable_totp(client, headers)
    stale_headers = dict(headers)

    resp = await client.post(
        "/api/v1/auth/totp/disable", json={"password": "correct-horse-battery-staple"}, headers=headers
    )
    assert resp.status_code == 204
    assert (await client.get("/api/v1/users/me/mfa-status", headers=stale_headers)).status_code == 401
    await refresh_headers(client, headers)
    assert (await client.get("/api/v1/users/me/mfa-status", headers=headers)).status_code == 200


async def test_webauthn_register_options_requires_auth(client, key_bundle_fields):
    resp = await client.post("/api/v1/auth/webauthn/register/options")
    assert resp.status_code == 401


async def test_webauthn_register_verify_requires_fresh_challenge(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)

    resp = await client.post("/api/v1/auth/webauthn/register/verify", json={"credential": {}}, headers=headers)
    assert resp.status_code == 400


async def test_webauthn_login_options_rejects_invalid_mfa_token(client, key_bundle_fields):
    resp = await client.post("/api/v1/auth/webauthn/login/options", json={"mfa_token": "garbage"})
    assert resp.status_code == 401


async def test_webauthn_login_options_rejects_user_with_no_passkeys(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)
    await enable_totp(client, headers)

    login_resp = await client.post(
        "/api/v1/auth/login", json={"email": "alice@example.com", "password": "correct-horse-battery-staple"}
    )
    mfa_token = login_resp.json()["mfa_token"]

    resp = await client.post("/api/v1/auth/webauthn/login/options", json={"mfa_token": mfa_token})
    assert resp.status_code == 400


async def test_login_events_records_logins_and_flags_new_device_once(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)

    resp = await client.get("/api/v1/users/me/login-events", headers=headers)
    events = resp.json()
    assert len(events) == 1
    assert events[0]["success"] is True
    assert events[0]["is_new_device"] is True

    await client.post(
        "/api/v1/auth/login", json={"email": "alice@example.com", "password": "correct-horse-battery-staple"}
    )

    resp = await client.get("/api/v1/users/me/login-events", headers=headers)
    events = resp.json()
    assert len(events) == 2
    assert {e["is_new_device"] for e in events} == {True, False}


async def _mfa_token(client):
    resp = await client.post(
        "/api/v1/auth/login", json={"email": "alice@example.com", "password": "correct-horse-battery-staple"}
    )
    return resp.json()["mfa_token"]


async def test_login_mfa_totp_rejects_replayed_code(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)
    secret = await enable_totp(client, headers)
    code = pyotp.TOTP(secret).now()

    resp = await client.post("/api/v1/auth/login/mfa/totp", json={"mfa_token": await _mfa_token(client), "code": code})
    assert resp.status_code == 200

    resp = await client.post("/api/v1/auth/login/mfa/totp", json={"mfa_token": await _mfa_token(client), "code": code})
    assert resp.status_code == 401


async def test_failed_totp_codes_lock_the_account(client, key_bundle_fields):
    headers = await register_and_login(client, key_bundle_fields)
    await enable_totp(client, headers)
    mfa_token = await _mfa_token(client)

    for _ in range(5):
        resp = await client.post("/api/v1/auth/login/mfa/totp", json={"mfa_token": mfa_token, "code": "000000"})
        assert resp.status_code == 401

    resp = await client.post(
        "/api/v1/auth/login", json={"email": "alice@example.com", "password": "correct-horse-battery-staple"}
    )
    assert resp.status_code == 423

    resp = await client.post("/api/v1/auth/webauthn/login/options", json={"mfa_token": mfa_token})
    assert resp.status_code == 423
