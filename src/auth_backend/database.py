"""Configuration de la base de données async SQLAlchemy."""
from collections.abc import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool

from .config import AuthConfig, get_config


class Base(DeclarativeBase):
    """Classe de base pour tous les modèles SQLAlchemy du module."""
    pass


# État global (initialisé par init_db)
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def init_db(config: AuthConfig | None = None) -> AsyncEngine:
    """Initialise le moteur SQLAlchemy et la session factory.

    À appeler une seule fois au démarrage de l'application.
    Si un moteur existe déjà, il est retourné tel quel (pas de réinitialisation).
    """
    global _engine, _session_factory

    if _engine is not None:
        return _engine

    cfg = config or get_config()

    engine_kwargs: dict = {
        "echo": cfg.db_echo,
        "pool_pre_ping": True,
        "future": True,
    }

    if cfg.db_use_null_pool:
        # En test : chaque connexion est jetable, pas de pool partagé
        # entre les boucles asyncio. Évite le RuntimeError
        # "Future attached to a different loop".
        engine_kwargs["poolclass"] = NullPool
    else:
        engine_kwargs["pool_size"] = cfg.db_pool_size
        engine_kwargs["max_overflow"] = cfg.db_max_overflow

    _engine = create_async_engine(cfg.database_url, **engine_kwargs)

    _session_factory = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )

    return _engine


def get_engine() -> AsyncEngine:
    """Retourne le moteur (initialise si nécessaire)."""
    if _engine is None:
        return init_db()
    return _engine


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dépendance FastAPI : fournit une session async par requête.

    Les services gèrent leurs propres commits.
    """
    if _session_factory is None:
        init_db()

    assert _session_factory is not None

    async with _session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def close_db() -> None:
    """Ferme le moteur et libère toutes les connexions.

    À appeler à l'arrêt de l'application, et entre chaque test
    pour éviter les conflits de boucle asyncio.
    """
    global _engine, _session_factory

    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None


async def create_all_tables() -> None:
    """Crée toutes les tables (utile en dev/test, pas en prod)."""
    from . import models  # noqa: F401 — import nécessaire pour enregistrer les modèles

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def drop_all_tables() -> None:
    """Supprime toutes les tables (dev/test uniquement)."""
    from . import models  # noqa: F401

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)