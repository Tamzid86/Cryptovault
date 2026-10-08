import base64
import binascii

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "CryptVault"
    environment: str = "development"

    database_url: str = "postgresql+asyncpg://cryptvault:cryptvault@localhost:5432/cryptvault"

    jwt_secret: str = "change-me-in-env"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    mfa_token_expire_minutes: int = 5

    refresh_cookie_name: str = "cv_refresh"
    refresh_cookie_secure: bool = True

    secret_encryption_key: str

    @field_validator("secret_encryption_key")
    @classmethod
    def _check_secret_encryption_key(cls, v: str) -> str:
        try:
            key = base64.b64decode(v, validate=True)
        except binascii.Error:
            key = b""
        if len(key) != 32:
            raise ValueError(
                "SECRET_ENCRYPTION_KEY must be base64 that decodes to exactly 32 bytes"
            )
        return v

    webauthn_rp_id: str = "localhost"
    webauthn_rp_name: str = "CryptVault"
    webauthn_origin: str = "http://localhost:5173"

    argon2_time_cost: int = 3
    argon2_memory_cost_kib: int = 65536
    argon2_parallelism: int = 4

    storage_path: str = "./data/chunks"
    max_chunk_size_bytes: int = 4 * 1024 * 1024
    max_storage_bytes_per_user: int = 1024 * 1024 * 1024

    rate_limit_login_per_minute: int = 5
    failed_login_lockout_threshold: int = 5
    lockout_duration_minutes: int = 15

    cors_origins: list[str] = ["http://localhost:5173"]


settings = Settings()
