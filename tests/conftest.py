"""Fixtures partagées pour les tests."""
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from auth_backend import AuthConfig, setup_auth
from auth_backend import database
from auth_backend.database import Base
from auth_backend import models  # noqa: F401

TEST_DATABASE_URL = (
    "postgresql+asyncpg://auth_user:auth_password_dev@localhost:5435/auth_db_test"
)



    
    
    
@pytest.fixture
def config() -> AuthConfig:
    return AuthConfig(
        database_url=TEST_DATABASE_URL,
        secret_key="test-secret-key-with-at-least-32-characters-long",
        api_prefix="/api/v1/auth",
        access_token_expire_minutes=30,
        refresh_token_expire_days=7,
        smtp_user="",
        smtp_password="",
        db_use_null_pool=True,
        email_console_fallback=True,   # ← ajout
        otp_rate_limit_per_hour=5,      # ← ajout
    )


@pytest_asyncio.fixture(autouse=True)
async def reset_engine() -> AsyncGenerator[None, None]:
    """Ferme l'engine globale avant et après chaque test.

    Cette fixture est appliquée automatiquement (autouse=True) et
    garantit qu'aucune connexion ne survit d'une boucle asyncio à
    l'autre. Sans cela, on obtient :
        RuntimeError: got Future attached to a different loop
    """
    await database.close_db()
    yield
    await database.close_db()


@pytest_asyncio.fixture
async def db_engine(config: AuthConfig):
    """Engine locale pour recréer le schéma avant chaque test.

    Note : on utilise NullPool ici aussi pour rester cohérent.
    """
    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
        poolclass=__import__("sqlalchemy.pool", fromlist=["NullPool"]).NullPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    """Session DB isolée pour les tests unitaires."""
    session_factory = async_sessionmaker(
        db_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with session_factory() as session:
        yield session


@pytest_asyncio.fixture
async def app(config: AuthConfig, db_engine) -> FastAPI:
    """Application FastAPI avec le module d'auth configuré."""
    app = FastAPI()
    setup_auth(app, config)
    return app


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    """Client HTTP async branché sur l'app FastAPI (ASGI)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
        
        
        
        
        
        
        
        
        
        
        
        
        
