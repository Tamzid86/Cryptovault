import shutil

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.db.session import get_db
from app.main import app


@pytest.fixture(scope="session", autouse=True)
def clean_chunk_storage():
    shutil.rmtree(settings.storage_path, ignore_errors=True)
    yield
    shutil.rmtree(settings.storage_path, ignore_errors=True)


@pytest_asyncio.fixture
async def db_session():
    engine = create_async_engine(settings.database_url, poolclass=NullPool)

    async with engine.connect() as conn:
        await conn.begin()
        await conn.begin_nested()
        session = AsyncSession(bind=conn, expire_on_commit=False)

        @event.listens_for(session.sync_session, "after_transaction_end")
        def restart_savepoint(sess, trans):
            if trans.nested and not trans._parent.nested:
                sess.begin_nested()

        yield session

        await session.close()
        await conn.rollback()

    await engine.dispose()


@pytest_asyncio.fixture
async def client(db_session):
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    app.state.limiter.reset()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture
def key_bundle_fields():
    import base64
    import os

    return {
        "public_key": base64.b64encode(os.urandom(32)).decode(),
        "encrypted_private_key": base64.b64encode(os.urandom(48)).decode(),
        "private_key_kdf_salt": base64.b64encode(os.urandom(16)).decode(),
        "private_key_nonce": base64.b64encode(os.urandom(12)).decode(),
    }
