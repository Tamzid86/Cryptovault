import uuid
from datetime import datetime

from pydantic import BaseModel


class CreateFileRequest(BaseModel):
    encrypted_filename: str
    filename_nonce: str
    size_bytes: int
    chunk_size: int
    num_chunks: int

    ephemeral_public_key: str
    wrapped_key: str
    wrap_nonce: str


class CreateFileResponse(BaseModel):
    id: uuid.UUID


class FileKeyShareOut(BaseModel):
    ephemeral_public_key: str
    wrapped_key: str
    wrap_nonce: str
    permission: str


class FileSummary(BaseModel):
    id: uuid.UUID
    owner_id: uuid.UUID
    encrypted_filename: str
    filename_nonce: str
    size_bytes: int
    chunk_size: int
    num_chunks: int
    created_at: datetime
    key_share: FileKeyShareOut
