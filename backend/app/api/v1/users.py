import base64

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.api.v1.files import storage_used_bytes
from app.core.config import settings
from app.db.session import get_db
from app.models.user import LoginEvent, User, WebAuthnCredential
from app.schemas.user import LoginEventOut, MfaStatusResponse, StorageUsageResponse, UserPublicKeyResponse

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me/mfa-status", response_model=MfaStatusResponse)
async def mfa_status(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    count = (
        await db.execute(select(func.count()).select_from(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id))
    ).scalar_one()
    return MfaStatusResponse(totp_enabled=user.totp_enabled, webauthn_credential_count=count)


@router.get("/me/storage", response_model=StorageUsageResponse)
async def storage_usage(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return StorageUsageResponse(
        used_bytes=await storage_used_bytes(db, user.id), quota_bytes=settings.max_storage_bytes_per_user
    )


@router.get("/me/login-events", response_model=list[LoginEventOut])
async def login_events(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    rows = (
        await db.execute(
            select(LoginEvent).where(LoginEvent.user_id == user.id).order_by(LoginEvent.created_at.desc()).limit(20)
        )
    ).scalars().all()
    return [
        LoginEventOut(
            ip_address=r.ip_address, user_agent=r.user_agent,
            success=r.success, is_new_device=r.is_new_device, created_at=r.created_at,
        )
        for r in rows
    ]


@router.get("/lookup", response_model=UserPublicKeyResponse)
async def lookup_user(
    email: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    target = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return UserPublicKeyResponse(
        id=target.id,
        email=target.email,
        public_key=base64.b64encode(target.public_key).decode(),
    )
