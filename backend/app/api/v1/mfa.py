import base64
import io
import json
from datetime import datetime, timedelta, timezone

import pyotp
import qrcode
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from app.api.deps import get_client_ip, get_current_user
from app.core.config import settings
from app.core.rate_limit import limiter
from app.core.security import decrypt_secret, encrypt_secret, verify_password
from app.db.session import get_db
from app.models.user import User, WebAuthnCredential
from app.schemas.auth import LoginResult
from app.schemas.mfa import (
    MfaTokenRequest,
    TotpCodeRequest,
    TotpDisableRequest,
    TotpSetupResponse,
    WebauthnLoginVerifyRequest,
    WebauthnRegisterVerifyRequest,
)
from app.services import audit
from app.services.login import complete_login, resolve_mfa_user, revoke_sessions

router = APIRouter(prefix="/auth", tags=["mfa"])

_WEBAUTHN_CHALLENGE_TTL = timedelta(minutes=5)


@router.post("/totp/setup", response_model=TotpSetupResponse)
async def totp_setup(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    secret = pyotp.random_base32()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=settings.app_name)

    qr_img = qrcode.make(uri)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    qr_data_uri = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()

    user.totp_secret_encrypted = encrypt_secret(secret.encode())
    user.totp_enabled = False
    user.totp_last_used_step = None
    await db.commit()

    return TotpSetupResponse(secret=secret, otpauth_uri=uri, qr_code_data_uri=qr_data_uri)


@router.post("/totp/verify", status_code=status.HTTP_204_NO_CONTENT)
async def totp_verify(
    request: Request,
    response: Response,
    body: TotpCodeRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if user.totp_secret_encrypted is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Call /auth/totp/setup first")

    secret = decrypt_secret(user.totp_secret_encrypted).decode()
    if not pyotp.TOTP(secret).verify(body.code, valid_window=1):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code")

    user.totp_enabled = True
    _revoke_other_sessions(user, response)
    await audit.append_entry(
        db, actor_id=user.id, action="mfa.totp_enabled", target_type="user",
        target_id=str(user.id), ip_address=get_client_ip(request),
    )
    await db.commit()


@router.post("/totp/disable", status_code=status.HTTP_204_NO_CONTENT)
async def totp_disable(
    request: Request,
    response: Response,
    body: TotpDisableRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect password")

    user.totp_enabled = False
    user.totp_secret_encrypted = None
    user.totp_last_used_step = None
    _revoke_other_sessions(user, response)
    await audit.append_entry(
        db, actor_id=user.id, action="mfa.totp_disabled", target_type="user",
        target_id=str(user.id), ip_address=get_client_ip(request),
    )
    await db.commit()


@router.post("/webauthn/register/options")
async def webauthn_register_options(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    existing = (
        await db.execute(select(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id))
    ).scalars().all()

    options = generate_registration_options(
        rp_id=settings.webauthn_rp_id,
        rp_name=settings.webauthn_rp_name,
        user_id=user.id.bytes,
        user_name=user.email,
        user_display_name=user.email,
        authenticator_selection=AuthenticatorSelectionCriteria(user_verification=UserVerificationRequirement.PREFERRED),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=c.credential_id) for c in existing],
    )
    user.webauthn_challenge = options.challenge
    user.webauthn_challenge_issued_at = datetime.now(timezone.utc)
    await db.commit()

    return json.loads(options_to_json(options))


@router.post("/webauthn/register/verify", status_code=status.HTTP_201_CREATED)
async def webauthn_register_verify(
    request: Request,
    response: Response,
    body: WebauthnRegisterVerifyRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _check_challenge_fresh(user)

    try:
        verification = verify_registration_response(
            credential=body.credential,
            expected_challenge=user.webauthn_challenge,
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=settings.webauthn_origin,
        )
    except WebAuthnException:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Could not verify passkey registration")

    db.add(
        WebAuthnCredential(
            user_id=user.id,
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
        )
    )
    user.webauthn_challenge = None
    user.webauthn_challenge_issued_at = None
    _revoke_other_sessions(user, response)
    await audit.append_entry(
        db, actor_id=user.id, action="mfa.webauthn_registered", target_type="user",
        target_id=str(user.id), ip_address=get_client_ip(request),
    )
    await db.commit()


@router.post("/webauthn/login/options")
@limiter.limit(f"{settings.rate_limit_login_per_minute}/minute")
async def webauthn_login_options(request: Request, body: MfaTokenRequest, db: AsyncSession = Depends(get_db)):
    user = await resolve_mfa_user(db, body.mfa_token)
    creds = (
        await db.execute(select(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id))
    ).scalars().all()
    if not creds:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No passkeys registered for this account")

    options = generate_authentication_options(
        rp_id=settings.webauthn_rp_id,
        allow_credentials=[PublicKeyCredentialDescriptor(id=c.credential_id) for c in creds],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    user.webauthn_challenge = options.challenge
    user.webauthn_challenge_issued_at = datetime.now(timezone.utc)
    await db.commit()

    return json.loads(options_to_json(options))


@router.post("/webauthn/login/verify", response_model=LoginResult)
@limiter.limit(f"{settings.rate_limit_login_per_minute}/minute")
async def webauthn_login_verify(
    request: Request, response: Response, body: WebauthnLoginVerifyRequest, db: AsyncSession = Depends(get_db)
):
    user = await resolve_mfa_user(db, body.mfa_token)
    _check_challenge_fresh(user)

    raw_id = base64url_to_bytes(body.credential.get("rawId") or body.credential.get("id", ""))
    cred_row = (
        await db.execute(
            select(WebAuthnCredential).where(
                WebAuthnCredential.credential_id == raw_id, WebAuthnCredential.user_id == user.id
            )
        )
    ).scalar_one_or_none()
    if cred_row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown passkey")

    try:
        verification = verify_authentication_response(
            credential=body.credential,
            expected_challenge=user.webauthn_challenge,
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=settings.webauthn_origin,
            credential_public_key=cred_row.public_key,
            credential_current_sign_count=cred_row.sign_count,
        )
    except WebAuthnException:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not verify passkey")

    cred_row.sign_count = verification.new_sign_count
    user.webauthn_challenge = None
    user.webauthn_challenge_issued_at = None

    return await complete_login(db, user, request, response, get_client_ip(request))


def _revoke_other_sessions(user: User, response: Response) -> None:
    revoke_sessions(user, response)


def _check_challenge_fresh(user: User) -> None:
    if user.webauthn_challenge is None or user.webauthn_challenge_issued_at is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No pending WebAuthn challenge")
    if datetime.now(timezone.utc) - user.webauthn_challenge_issued_at > _WEBAUTHN_CHALLENGE_TTL:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="WebAuthn challenge expired, start over")
