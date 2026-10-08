import base64
import os
import shutil
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from app.api.deps import get_client_ip, get_current_user
from app.core.config import settings
from app.db.session import get_db
from app.models.file import FileChunk, FileKeyShare, FileObject, Permission
from app.models.user import User
from app.schemas.file import CreateFileRequest, CreateFileResponse, FileKeyShareOut, FileSummary
from app.schemas.share import CreateShareRequest, ShareOut
from app.services import audit

router = APIRouter(prefix="/files", tags=["files"])

_GCM_TAG_OVERHEAD = 16


def _b64decode(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid base64 field")


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode()


def _chunk_dir(file_id: uuid.UUID) -> str:
    return os.path.join(settings.storage_path, str(file_id))


def _write_chunk(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def _read_chunk(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _expected_num_chunks(size_bytes: int, chunk_size: int) -> int:
    return max(1, -(-size_bytes // chunk_size))


async def storage_used_bytes(db: AsyncSession, user_id: uuid.UUID) -> int:
    return (
        await db.execute(select(func.coalesce(func.sum(FileObject.size_bytes), 0)).where(FileObject.owner_id == user_id))
    ).scalar_one()


async def _get_file_with_access(db: AsyncSession, file_id: uuid.UUID, user_id: uuid.UUID) -> FileObject:
    result = await db.execute(
        select(FileObject)
        .join(FileKeyShare, FileKeyShare.file_id == FileObject.id)
        .where(FileObject.id == file_id, FileKeyShare.recipient_id == user_id)
    )
    file = result.scalar_one_or_none()
    if file is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    return file


async def _require_owner_share(db: AsyncSession, file_id: uuid.UUID, user_id: uuid.UUID) -> FileObject:
    file = await _get_file_with_access(db, file_id, user_id)
    share = (
        await db.execute(
            select(FileKeyShare).where(FileKeyShare.file_id == file_id, FileKeyShare.recipient_id == user_id)
        )
    ).scalar_one()
    if share.permission != Permission.OWNER:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the file owner can manage sharing")
    return file


@router.post("", response_model=CreateFileResponse, status_code=status.HTTP_201_CREATED)
async def create_file(
    request: Request,
    body: CreateFileRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if body.num_chunks < 1 or body.size_bytes < 0 or body.chunk_size < 1:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid file metadata")
    if body.chunk_size > settings.max_chunk_size_bytes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Chunk size exceeds server limit")
    if body.num_chunks != _expected_num_chunks(body.size_bytes, body.chunk_size):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="num_chunks does not match size_bytes")

    await db.execute(select(User.id).where(User.id == user.id).with_for_update())
    if await storage_used_bytes(db, user.id) + body.size_bytes > settings.max_storage_bytes_per_user:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="Storage quota exceeded")

    file = FileObject(
        owner_id=user.id,
        encrypted_filename=_b64decode(body.encrypted_filename),
        filename_nonce=_b64decode(body.filename_nonce),
        size_bytes=body.size_bytes,
        chunk_size=body.chunk_size,
        num_chunks=body.num_chunks,
    )
    db.add(file)
    await db.flush()

    db.add(
        FileKeyShare(
            file_id=file.id,
            recipient_id=user.id,
            granted_by_id=user.id,
            ephemeral_public_key=_b64decode(body.ephemeral_public_key),
            wrapped_key=_b64decode(body.wrapped_key),
            wrap_nonce=_b64decode(body.wrap_nonce),
            permission=Permission.OWNER,
        )
    )

    await audit.append_entry(
        db, actor_id=user.id, action="file.create", target_type="file",
        target_id=str(file.id), ip_address=get_client_ip(request),
    )
    await db.commit()
    return CreateFileResponse(id=file.id)


@router.get("", response_model=list[FileSummary])
async def list_files(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(FileObject, FileKeyShare)
        .join(FileKeyShare, FileKeyShare.file_id == FileObject.id)
        .where(FileKeyShare.recipient_id == user.id)
        .order_by(FileObject.created_at.desc())
    )
    return [
        FileSummary(
            id=f.id,
            owner_id=f.owner_id,
            encrypted_filename=_b64encode(f.encrypted_filename),
            filename_nonce=_b64encode(f.filename_nonce),
            size_bytes=f.size_bytes,
            chunk_size=f.chunk_size,
            num_chunks=f.num_chunks,
            created_at=f.created_at,
            key_share=FileKeyShareOut(
                ephemeral_public_key=_b64encode(ks.ephemeral_public_key),
                wrapped_key=_b64encode(ks.wrapped_key),
                wrap_nonce=_b64encode(ks.wrap_nonce),
                permission=ks.permission.value,
            ),
        )
        for f, ks in result.all()
    ]


@router.put("/{file_id}/chunks/{chunk_index}", status_code=status.HTTP_204_NO_CONTENT)
async def upload_chunk(
    file_id: uuid.UUID,
    chunk_index: int,
    request: Request,
    x_chunk_nonce: str = Header(...),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(FileObject).where(FileObject.id == file_id, FileObject.owner_id == user.id)
    )
    file = result.scalar_one_or_none()
    if file is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    if not (0 <= chunk_index < file.num_chunks):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Chunk index out of range")

    max_plaintext = min(file.chunk_size, file.size_bytes - chunk_index * file.chunk_size)
    body = await request.body()
    if len(body) > max_plaintext + _GCM_TAG_OVERHEAD:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Chunk exceeds declared chunk size")

    nonce = _b64decode(x_chunk_nonce)
    path = os.path.join(_chunk_dir(file_id), f"{chunk_index}.bin")
    await run_in_threadpool(_write_chunk, path, body)

    existing = await db.execute(
        select(FileChunk).where(FileChunk.file_id == file_id, FileChunk.chunk_index == chunk_index)
    )
    chunk = existing.scalar_one_or_none()
    if chunk is None:
        db.add(FileChunk(file_id=file_id, chunk_index=chunk_index, nonce=nonce, storage_path=path, size_bytes=len(body)))
    else:
        chunk.nonce = nonce
        chunk.size_bytes = len(body)

    await db.commit()


@router.get("/{file_id}/chunks/{chunk_index}")
async def download_chunk(
    file_id: uuid.UUID,
    chunk_index: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _get_file_with_access(db, file_id, user.id)

    result = await db.execute(
        select(FileChunk).where(FileChunk.file_id == file_id, FileChunk.chunk_index == chunk_index)
    )
    chunk = result.scalar_one_or_none()
    if chunk is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Chunk not found")

    data = await run_in_threadpool(_read_chunk, chunk.storage_path)
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"X-Chunk-Nonce": _b64encode(chunk.nonce)},
    )


@router.delete("/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_file(
    file_id: uuid.UUID,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(FileObject).where(FileObject.id == file_id, FileObject.owner_id == user.id))
    file = result.scalar_one_or_none()
    if file is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")

    await run_in_threadpool(shutil.rmtree, _chunk_dir(file_id), True)
    await db.delete(file)

    await audit.append_entry(
        db, actor_id=user.id, action="file.delete", target_type="file",
        target_id=str(file_id), ip_address=get_client_ip(request),
    )
    await db.commit()


@router.post("/{file_id}/shares", response_model=ShareOut, status_code=status.HTTP_201_CREATED)
async def create_share(
    file_id: uuid.UUID,
    body: CreateShareRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_owner_share(db, file_id, user.id)

    if body.recipient_email == user.email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You already own this file")

    recipient = (await db.execute(select(User).where(User.email == body.recipient_email))).scalar_one_or_none()
    if recipient is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    existing = (
        await db.execute(
            select(FileKeyShare).where(FileKeyShare.file_id == file_id, FileKeyShare.recipient_id == recipient.id)
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Already shared with this user")

    share = FileKeyShare(
        file_id=file_id,
        recipient_id=recipient.id,
        granted_by_id=user.id,
        ephemeral_public_key=_b64decode(body.ephemeral_public_key),
        wrapped_key=_b64decode(body.wrapped_key),
        wrap_nonce=_b64decode(body.wrap_nonce),
        permission=Permission.READ,
    )
    db.add(share)
    await db.flush()

    await audit.append_entry(
        db, actor_id=user.id, action="file.share.create", target_type="file",
        target_id=str(file_id), ip_address=get_client_ip(request),
    )
    await db.commit()

    return ShareOut(
        recipient_id=recipient.id,
        recipient_email=recipient.email,
        permission=share.permission.value,
        created_at=share.created_at,
    )


@router.get("/{file_id}/shares", response_model=list[ShareOut])
async def list_shares(
    file_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_owner_share(db, file_id, user.id)

    result = await db.execute(
        select(FileKeyShare, User)
        .join(User, User.id == FileKeyShare.recipient_id)
        .where(FileKeyShare.file_id == file_id)
        .order_by(FileKeyShare.created_at)
    )
    return [
        ShareOut(
            recipient_id=recipient.id,
            recipient_email=recipient.email,
            permission=share.permission.value,
            created_at=share.created_at,
        )
        for share, recipient in result.all()
    ]


@router.delete("/{file_id}/shares/{recipient_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_share(
    file_id: uuid.UUID,
    recipient_id: uuid.UUID,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _require_owner_share(db, file_id, user.id)

    share = (
        await db.execute(
            select(FileKeyShare).where(FileKeyShare.file_id == file_id, FileKeyShare.recipient_id == recipient_id)
        )
    ).scalar_one_or_none()
    if share is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Share not found")
    if share.permission == Permission.OWNER:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot revoke the owner's own access")

    await db.delete(share)

    await audit.append_entry(
        db, actor_id=user.id, action="file.share.revoke", target_type="file",
        target_id=str(file_id), ip_address=get_client_ip(request),
    )
    await db.commit()
