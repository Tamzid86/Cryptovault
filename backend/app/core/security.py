import base64
import os
import uuid
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jose import JWTError, jwt

from app.core.config import settings

_hasher = PasswordHasher(
    time_cost=settings.argon2_time_cost,
    memory_cost=settings.argon2_memory_cost_kib,
    parallelism=settings.argon2_parallelism,
)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)




def create_access_token(subject: str, version: int) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {"sub": subject, "exp": expire, "type": "access", "ver": version, "jti": uuid.uuid4().hex}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_refresh_token(subject: str, version: int) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
    payload = {"sub": subject, "exp": expire, "type": "refresh", "ver": version, "jti": uuid.uuid4().hex}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_mfa_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.mfa_token_expire_minutes)
    payload = {"sub": subject, "exp": expire, "type": "mfa_pending", "jti": uuid.uuid4().hex}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError:
        return None


_SECRET_KEY = base64.b64decode(settings.secret_encryption_key)


def encrypt_secret(plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    ciphertext = AESGCM(_SECRET_KEY).encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt_secret(blob: bytes) -> bytes:
    nonce, ciphertext = blob[:12], blob[12:]
    try:
        return AESGCM(_SECRET_KEY).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("Secret ciphertext failed authentication")
