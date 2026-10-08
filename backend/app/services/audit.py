import hashlib
import uuid

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLogEntry

GENESIS_HASH = "0" * 64

_AUDIT_CHAIN_LOCK_KEY = 0x43565F4155444954


def _compute_entry_hash(prev_hash: str, actor_id: str, action: str, target_type: str, target_id: str, created_at: str) -> str:
    payload = f"{prev_hash}|{actor_id}|{action}|{target_type}|{target_id}|{created_at}".encode()
    return hashlib.sha256(payload).hexdigest()


async def append_entry(
    db: AsyncSession,
    *,
    actor_id: uuid.UUID | None,
    action: str,
    target_type: str,
    target_id: str,
    ip_address: str,
) -> AuditLogEntry:
    await db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _AUDIT_CHAIN_LOCK_KEY})

    last = (
        await db.execute(select(AuditLogEntry).order_by(AuditLogEntry.sequence.desc()).limit(1))
    ).scalar_one_or_none()
    prev_hash = last.entry_hash if last else GENESIS_HASH

    from datetime import datetime, timezone

    created_at = datetime.now(timezone.utc)
    entry_hash = _compute_entry_hash(
        prev_hash, str(actor_id), action, target_type, target_id, created_at.isoformat()
    )

    entry = AuditLogEntry(
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        ip_address=ip_address,
        created_at=created_at,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    db.add(entry)
    await db.flush()
    return entry


async def verify_chain(db: AsyncSession) -> tuple[bool, int | None]:
    rows = (await db.execute(select(AuditLogEntry).order_by(AuditLogEntry.sequence.asc()))).scalars().all()

    prev_hash = GENESIS_HASH
    for row in rows:
        expected = _compute_entry_hash(
            prev_hash, str(row.actor_id), row.action, row.target_type, row.target_id, row.created_at.isoformat()
        )
        if expected != row.entry_hash or row.prev_hash != prev_hash:
            return False, row.sequence
        prev_hash = row.entry_hash

    return True, None
