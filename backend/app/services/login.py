import base64
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import pyotp
from fastapi import HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import create_access_token, create_refresh_token, decode_token
from app.models.user import LoginEvent, User
from app.schemas.auth import KeyBundleResponse, LoginResult, TokenPair
from app.services import audit


_REFRESH_COOKIE_PATH = "/api/v1/auth"


def set_refresh_cookie(response: Response, user: User) -> None:
    response.set_cookie(
        settings.refresh_cookie_name,
        create_refresh_token(str(user.id), user.token_version),
        max_age=settings.refresh_token_expire_days * 24 * 3600,
        path=_REFRESH_COOKIE_PATH,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite="strict",
    )


def clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        settings.refresh_cookie_name,
        path=_REFRESH_COOKIE_PATH,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite="strict",
    )


def revoke_sessions(user: User, response: Response | None = None) -> str | None:
    user.token_version += 1
    if response is None:
        return None
    set_refresh_cookie(response, user)
    return create_access_token(str(user.id), user.token_version)


def token_matches_user(payload: dict, user: User) -> bool:
    return payload.get("ver") == user.token_version


def device_fingerprint(user_agent: str, ip: str) -> str:
    return hashlib.sha256(f"{user_agent}|{ip}".encode()).hexdigest()


async def resolve_mfa_user(db: AsyncSession, mfa_token: str) -> User:
    unauthorized = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired MFA session")

    payload = decode_token(mfa_token)
    if payload is None or payload.get("type") != "mfa_pending":
        raise unauthorized

    try:
        user_id = uuid.UUID(payload["sub"])
    except (KeyError, ValueError):
        raise unauthorized

    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None:
        raise unauthorized

    raise_if_locked(user)

    return user


def raise_if_locked(user: User) -> None:
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Account locked until {user.locked_until.isoformat()}",
        )


async def record_failed_attempt(db: AsyncSession, user: User) -> None:
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= settings.failed_login_lockout_threshold:
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=settings.lockout_duration_minutes)


def match_totp_step(secret: str, code: str, valid_window: int = 1) -> int | None:
    totp = pyotp.TOTP(secret)
    now = datetime.now(timezone.utc)
    for offset in range(-valid_window, valid_window + 1):
        t = now + timedelta(seconds=offset * totp.interval)
        if pyotp.utils.strings_equal(totp.at(t), code):
            return totp.timecode(t)
    return None


async def complete_login(db: AsyncSession, user: User, request: Request, response: Response, ip: str) -> LoginResult:
    user_agent = request.headers.get("user-agent", "unknown")
    user.failed_login_attempts = 0
    user.locked_until = None

    fingerprint = device_fingerprint(user_agent, ip)
    seen_before = (
        await db.execute(
            select(LoginEvent)
            .where(
                LoginEvent.user_id == user.id,
                LoginEvent.device_fingerprint == fingerprint,
                LoginEvent.success.is_(True),
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    is_new_device = seen_before is None

    db.add(
        LoginEvent(
            user_id=user.id, ip_address=ip, user_agent=user_agent,
            device_fingerprint=fingerprint, success=True, is_new_device=is_new_device,
        )
    )
    await audit.append_entry(
        db, actor_id=user.id, action="auth.login_succeeded",
        target_type="user", target_id=str(user.id), ip_address=ip,
    )
    await db.commit()

    set_refresh_cookie(response, user)
    return LoginResult(
        tokens=TokenPair(access_token=create_access_token(str(user.id), user.token_version)),
        key_bundle=KeyBundleResponse(
            public_key=base64.b64encode(user.public_key).decode(),
            encrypted_private_key=base64.b64encode(user.encrypted_private_key).decode(),
            private_key_kdf_salt=base64.b64encode(user.private_key_kdf_salt).decode(),
            private_key_nonce=base64.b64encode(user.private_key_nonce).decode(),
        ),
    )
