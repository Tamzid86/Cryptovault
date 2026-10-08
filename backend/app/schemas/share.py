import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr


class CreateShareRequest(BaseModel):
    recipient_email: EmailStr
    ephemeral_public_key: str
    wrapped_key: str
    wrap_nonce: str


class ShareOut(BaseModel):
    recipient_id: uuid.UUID
    recipient_email: str
    permission: str
    created_at: datetime
