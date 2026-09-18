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
def config(tmp_path) -> AuthConfig:
    from cryptography.fernet import Fernet

    return AuthConfig(
        database_url=TEST_DATABASE_URL,
        secret_key="test-secret-key-with-at-least-32-characters-long",
        api_prefix="/api/v1/auth",
        access_token_expire_minutes=30,
        refresh_token_expire_days=7,
        smtp_user="",
        smtp_password="",
        db_use_null_pool=True,
        email_console_fallback=True,
        otp_rate_limit_per_hour=5,
        webauthn_rp_id="test",
        webauthn_rp_name="Auth Test",
        webauthn_origin="http://test",
        # Vérification d'identité
        verification_encryption_key=Fernet.generate_key().decode(),
        verification_storage_path=str(tmp_path / "storage" / "verifications"),
        verification_upload_max_mb=5,
        verification_max_attempts=3,
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
        
 



@pytest_asyncio.fixture
async def admin_client(app, db_engine) -> AsyncGenerator[AsyncClient, None]:
    """Client HTTP dont l'utilisateur est admin."""
    from auth_backend.database import get_db  # noqa
    from auth_backend import database
    from auth_backend.models import User
    from sqlalchemy import select

    # Créer un admin via l'API
    admin_data = {
        "email": "admin@example.com",
        "display_name": "Admin User",
        "password": "AdminPassword123!",
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        # Inscription
        await c.post("/api/v1/auth/register", json=admin_data)

        # Passer is_admin=True en DB
        session_factory = database._session_factory
        assert session_factory is not None
        async with session_factory() as session:
            stmt = select(User).where(User.email == "admin@example.com")
            result = await session.execute(stmt)
            user = result.scalar_one_or_none()
            if user:
                user.is_admin = True
                await session.commit()

        # Connexion
        login = await c.post(
            "/api/v1/auth/token",
            data={"username": "admin@example.com", "password": "AdminPassword123!"},
        )
        token = login.json()["access_token"]

        # Ajouter le header par défaut
        c.headers["Authorization"] = f"Bearer {token}"
        yield c 
        
        
        
        
        
        
        
        
        
        
        
