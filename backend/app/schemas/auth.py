import uuid

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)
    public_key: str
    encrypted_private_key: str
    private_key_kdf_salt: str
    private_key_nonce: str


class RegisterResponse(BaseModel):
    id: uuid.UUID
    email: EmailStr


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenPair(BaseModel):
    access_token: str
    token_type: str = "bearer"


class RefreshResponse(TokenPair):
    email: EmailStr


class KeyBundleResponse(BaseModel):
    public_key: str
    encrypted_private_key: str
    private_key_kdf_salt: str
    private_key_nonce: str


class LoginResult(BaseModel):
    mfa_required: bool = False
    methods: list[str] | None = None
    mfa_token: str | None = None
    tokens: TokenPair | None = None
    key_bundle: KeyBundleResponse | None = None


class TotpMfaRequest(BaseModel):
    mfa_token: str
    code: str
