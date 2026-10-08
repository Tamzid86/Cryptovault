import pytest
from sqlalchemy import select

from app.main import app
from app.models.audit import AuditLogEntry
from app.models.user import User
from app.services import audit

pytestmark = pytest.mark.asyncio


async def register(client, email, key_bundle_fields, password="correct-horse-battery-staple"):
    return await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password, **key_bundle_fields},
    )


async def test_register_returns_id_and_email(client, key_bundle_fields):
    resp = await register(client, "alice@example.com", key_bundle_fields)
    assert resp.status_code == 201
    body = resp.json()
    assert body["email"] == "alice@example.com"
    assert "id" in body


async def test_register_rejects_duplicate_email(client, key_bundle_fields):
    await register(client, "alice@example.com", key_bundle_fields)
    resp = await register(client, "alice@example.com", key_bundle_fields)
    assert resp.status_code == 400


async def test_register_rejects_short_password(client, key_bundle_fields):
    resp = await register(client, "alice@example.com", key_bundle_fields, password="short")
    assert resp.status_code == 422


async def test_login_success_returns_tokens_and_key_bundle(client, key_bundle_fields):
    await register(client, "alice@example.com", key_bundle_fields)

    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "password": "correct-horse-battery-staple"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["tokens"]["access_token"]
    assert "refresh_token" not in body["tokens"]
    cookie = resp.headers["set-cookie"]
    assert "cv_refresh=" in cookie and "HttpOnly" in cookie and "SameSite=strict" in cookie and "Secure" in cookie
    assert body["key_bundle"]["public_key"] == key_bundle_fields["public_key"]
    assert body["key_bundle"]["encrypted_private_key"] == key_bundle_fields["encrypted_private_key"]


async def test_login_rejects_wrong_password(client, key_bundle_fields):
    await register(client, "alice@example.com", key_bundle_fields)

    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "password": "totally-wrong-password"},
    )
    assert resp.status_code == 401
    assert "key_bundle" not in resp.json()


async def test_login_rejects_unknown_email_without_500(client):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@example.com", "password": "whatever-12345"},
    )
    assert resp.status_code == 401


async def test_account_locks_after_threshold_failed_attempts(client, db_session, key_bundle_fields):
    await register(client, "alice@example.com", key_bundle_fields)

    for _ in range(5):
        app.state.limiter.reset()
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "alice@example.com", "password": "wrong-password"},
        )
        assert resp.status_code == 401

    app.state.limiter.reset()
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "password": "correct-horse-battery-staple"},
    )
    assert resp.status_code == 423

    user = (await db_session.execute(select(User).where(User.email == "alice@example.com"))).scalar_one()
    assert user.locked_until is not None


async def test_locked_account_does_not_reveal_whether_password_is_correct(client, key_bundle_fields):
    await register(client, "alice@example.com", key_bundle_fields)

    for _ in range(5):
        app.state.limiter.reset()
        await client.post("/api/v1/auth/login", json={"email": "alice@example.com", "password": "wrong-password"})

    responses = []
    for password in ("another-wrong-guess", "correct-horse-battery-staple"):
        app.state.limiter.reset()
        resp = await client.post("/api/v1/auth/login", json={"email": "alice@example.com", "password": password})
        responses.append((resp.status_code, resp.json()))

    assert responses[0][0] == 423
    assert responses[0] == responses[1]


async def test_audit_chain_records_register_and_login_and_verifies(client, db_session, key_bundle_fields):
    user_id = (await register(client, "alice@example.com", key_bundle_fields)).json()["id"]
    await client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "password": "correct-horse-battery-staple"},
    )

    entries = (
        await db_session.execute(
            select(AuditLogEntry).where(AuditLogEntry.actor_id == user_id).order_by(AuditLogEntry.sequence)
        )
    ).scalars().all()
    actions = [e.action for e in entries]
    assert actions == ["user.register", "auth.login_succeeded"]

    ok, bad_seq = await audit.verify_chain(db_session)
    assert ok is True
    assert bad_seq is None


async def test_audit_chain_detects_tampering(client, db_session, key_bundle_fields):
    user_id = (await register(client, "alice@example.com", key_bundle_fields)).json()["id"]

    entry = (
        await db_session.execute(select(AuditLogEntry).where(AuditLogEntry.actor_id == user_id))
    ).scalar_one()
    entry.action = "user.register.TAMPERED"
    await db_session.flush()

    ok, bad_seq = await audit.verify_chain(db_session)
    assert ok is False
    assert bad_seq == entry.sequence


async def _login(client, key_bundle_fields):
    await register(client, "alice@example.com", key_bundle_fields)
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "password": "correct-horse-battery-staple"},
    )
    return resp


async def test_refresh_uses_cookie_and_issues_working_access_token(client, key_bundle_fields):
    await _login(client, key_bundle_fields)
    old_cookie = client.cookies.get("cv_refresh")

    resp = await client.post("/api/v1/auth/refresh")
    assert resp.status_code == 200
    body = resp.json()
    assert body["email"] == "alice@example.com"
    assert client.cookies.get("cv_refresh") != old_cookie

    resp = await client.get(
        "/api/v1/users/me/mfa-status", headers={"Authorization": f"Bearer {body['access_token']}"}
    )
    assert resp.status_code == 200


async def test_refresh_rejects_missing_garbage_and_access_token_cookie(client, key_bundle_fields):
    resp = await _login(client, key_bundle_fields)
    access_token = resp.json()["tokens"]["access_token"]

    client.cookies.clear()
    assert (await client.post("/api/v1/auth/refresh")).status_code == 401

    client.cookies.set("cv_refresh", "garbage", domain="test.local", path="/api/v1/auth")
    assert (await client.post("/api/v1/auth/refresh")).status_code == 401

    client.cookies.clear()
    client.cookies.set("cv_refresh", access_token, domain="test.local", path="/api/v1/auth")
    assert (await client.post("/api/v1/auth/refresh")).status_code == 401


async def test_refresh_token_is_not_accepted_as_access_token(client, key_bundle_fields):
    await _login(client, key_bundle_fields)
    refresh_token = client.cookies.get("cv_refresh")

    resp = await client.get("/api/v1/users/me/mfa-status", headers={"Authorization": f"Bearer {refresh_token}"})
    assert resp.status_code == 401


async def test_logout_clears_refresh_cookie(client, key_bundle_fields):
    await _login(client, key_bundle_fields)
    assert client.cookies.get("cv_refresh")

    resp = await client.post("/api/v1/auth/logout")
    assert resp.status_code == 204
    assert client.cookies.get("cv_refresh") is None
    assert (await client.post("/api/v1/auth/refresh")).status_code == 401


async def test_client_supplied_x_forwarded_for_is_ignored(client, key_bundle_fields):
    await register(client, "alice@example.com", key_bundle_fields)
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.com", "password": "correct-horse-battery-staple"},
        headers={"X-Forwarded-For": "6.6.6.6"},
    )
    headers = {"Authorization": f"Bearer {resp.json()['tokens']['access_token']}"}

    events = (await client.get("/api/v1/users/me/login-events", headers=headers)).json()
    assert all(e["ip_address"] != "6.6.6.6" for e in events)


async def test_logout_all_revokes_every_copy_of_the_session(client, key_bundle_fields):
    resp = await _login(client, key_bundle_fields)
    headers = {"Authorization": f"Bearer {resp.json()['tokens']['access_token']}"}
    copied_refresh = client.cookies.get("cv_refresh")

    resp = await client.post("/api/v1/auth/logout-all", headers=headers)
    assert resp.status_code == 204
    assert client.cookies.get("cv_refresh") is None

    client.cookies.set("cv_refresh", copied_refresh, domain="test.local", path="/api/v1/auth")
    assert (await client.post("/api/v1/auth/refresh")).status_code == 401
    assert (await client.get("/api/v1/users/me/mfa-status", headers=headers)).status_code == 401

    resp = await client.post("/api/v1/auth/login", json={"email": "alice@example.com", "password": "correct-horse-battery-staple"})
    assert resp.status_code == 200
    new_headers = {"Authorization": f"Bearer {resp.json()['tokens']['access_token']}"}
    assert (await client.get("/api/v1/users/me/mfa-status", headers=new_headers)).status_code == 200


async def test_logout_all_requires_auth(client):
    assert (await client.post("/api/v1/auth/logout-all")).status_code == 401
