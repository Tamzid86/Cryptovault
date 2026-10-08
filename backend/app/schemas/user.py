import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr


class UserPublicKeyResponse(BaseModel):
    id: uuid.UUID
    email: EmailStr
    public_key: str


class LoginEventOut(BaseModel):
    ip_address: str
    user_agent: str
    success: bool
    is_new_device: bool
    created_at: datetime


class MfaStatusResponse(BaseModel):
    totp_enabled: bool
    webauthn_credential_count: int


class StorageUsageResponse(BaseModel):
    used_bytes: int
    quota_bytes: int
