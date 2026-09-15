"""Configuration de la base de données async SQLAlchemy."""
from collections.abc import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
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
    """
    global _engine, _session_factory
    
    if _engine is not None:
        return _engine
    
    cfg = config or get_config()
    
    _engine = create_async_engine(
        cfg.database_url,
        echo=cfg.db_echo,
        pool_size=cfg.db_pool_size,
        max_overflow=cfg.db_max_overflow,
        pool_pre_ping=True,  # Vérifie la connexion avant utilisation
        future=True,
    )
    
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
    """Dépendance FastAPI : fournit une session async par requête."""
    if _session_factory is None:
        init_db()
    
    assert _session_factory is not None
    
    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def close_db() -> None:
    """Ferme le moteur (à appeler à l'arrêt de l'application)."""
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
