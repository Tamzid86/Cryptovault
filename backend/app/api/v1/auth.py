import base64
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_client_ip, get_current_user
from app.core.config import settings
from app.core.rate_limit import limiter
from app.core.security import (
    create_access_token,
    create_mfa_token,
    decode_token,
    decrypt_secret,
    hash_password,
    verify_password,
)
from app.db.session import get_db
from app.models.user import LoginEvent, User, WebAuthnCredential
from app.schemas.auth import (
    LoginRequest,
    LoginResult,
    RefreshResponse,
    RegisterRequest,
    RegisterResponse,
    TotpMfaRequest,
)
from app.services import audit
from app.services.login import (
    clear_refresh_cookie,
    complete_login,
    device_fingerprint,
    match_totp_step,
    raise_if_locked,
    record_failed_attempt,
    resolve_mfa_user,
    revoke_sessions,
    set_refresh_cookie,
    token_matches_user,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def _b64decode(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid base64 field")


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("3/minute")
async def register(request: Request, body: RegisterRequest, db: AsyncSession = Depends(get_db)):
    existing = (await db.execute(select(User).where(User.email == body.email))).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Registration failed")

    user = User(
        email=body.email,
        password_hash=hash_password(body.password),
        public_key=_b64decode(body.public_key),
        encrypted_private_key=_b64decode(body.encrypted_private_key),
        private_key_kdf_salt=_b64decode(body.private_key_kdf_salt),
        private_key_nonce=_b64decode(body.private_key_nonce),
    )
    db.add(user)
    await db.flush()

    await audit.append_entry(
        db,
        actor_id=user.id,
        action="user.register",
        target_type="user",
        target_id=str(user.id),
        ip_address=get_client_ip(request),
    )
    await db.commit()

    return RegisterResponse(id=user.id, email=user.email)


@router.post("/login", response_model=LoginResult)
@limiter.limit(f"{settings.rate_limit_login_per_minute}/minute")
async def login(request: Request, response: Response, body: LoginRequest, db: AsyncSession = Depends(get_db)):
    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "unknown")
    invalid_credentials = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    user = (await db.execute(select(User).where(User.email == body.email))).scalar_one_or_none()

    dummy_hash = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    password_ok = verify_password(body.password, user.password_hash if user else dummy_hash)

    if user is not None:
        raise_if_locked(user)

    if user is None or not password_ok:
        if user is not None:
            await record_failed_attempt(db, user)
            db.add(LoginEvent(
                user_id=user.id, ip_address=ip, user_agent=user_agent,
                device_fingerprint=device_fingerprint(user_agent, ip), success=False, is_new_device=False,
            ))
            await audit.append_entry(
                db, actor_id=user.id, action="auth.login_failed",
                target_type="user", target_id=str(user.id), ip_address=ip,
            )
            await db.commit()
        raise invalid_credentials

    has_webauthn = (
        await db.execute(select(WebAuthnCredential.id).where(WebAuthnCredential.user_id == user.id).limit(1))
    ).scalar_one_or_none() is not None

    if user.totp_enabled or has_webauthn:
        methods = []
        if user.totp_enabled:
            methods.append("totp")
        if has_webauthn:
            methods.append("webauthn")
        return LoginResult(mfa_required=True, methods=methods, mfa_token=create_mfa_token(str(user.id)))

    return await complete_login(db, user, request, response, ip)


@router.post("/login/mfa/totp", response_model=LoginResult)
@limiter.limit(f"{settings.rate_limit_login_per_minute}/minute")
async def login_mfa_totp(
    request: Request, response: Response, body: TotpMfaRequest, db: AsyncSession = Depends(get_db)
):
    user = await resolve_mfa_user(db, body.mfa_token)
    if not user.totp_enabled or user.totp_secret_encrypted is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="TOTP is not enabled for this account")

    ip = get_client_ip(request)
    secret = decrypt_secret(user.totp_secret_encrypted).decode()
    step = match_totp_step(secret, body.code)
    replayed = step is not None and user.totp_last_used_step is not None and step <= user.totp_last_used_step

    if step is None or replayed:
        await record_failed_attempt(db, user)
        await audit.append_entry(
            db, actor_id=user.id, action="auth.mfa_failed",
            target_type="user", target_id=str(user.id), ip_address=ip,
        )
        await db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid code")

    user.totp_last_used_step = step
    return await complete_login(db, user, request, response, ip)


@router.post("/refresh", response_model=RefreshResponse)
@limiter.limit("30/minute")
async def refresh(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    unauthorized = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")

    token = request.cookies.get(settings.refresh_cookie_name)
    payload = decode_token(token) if token else None
    if payload is None or payload.get("type") != "refresh":
        raise unauthorized

    try:
        user_id = uuid.UUID(payload["sub"])
    except (KeyError, ValueError):
        raise unauthorized

    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None or not token_matches_user(payload, user):
        raise unauthorized

    set_refresh_cookie(response, user)
    return RefreshResponse(access_token=create_access_token(str(user.id), user.token_version), email=user.email)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(response: Response):
    clear_refresh_cookie(response)


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(
    request: Request, response: Response, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    revoke_sessions(user)
    await audit.append_entry(
        db, actor_id=user.id, action="auth.sessions_revoked",
        target_type="user", target_id=str(user.id), ip_address=get_client_ip(request),
    )
    await db.commit()
    clear_refresh_cookie(response)
