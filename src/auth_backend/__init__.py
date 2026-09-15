"""Module d'authentification réutilisable pour FastAPI.

Utilisation typique:

    from fastapi import FastAPI
    from auth_backend import setup_auth, AuthConfig

    app = FastAPI()
    setup_auth(app, AuthConfig(
        database_url="postgresql+asyncpg://...",
        secret_key="...",
    ))
"""
from fastapi import FastAPI

from .config import AuthConfig, get_config
from .database import close_db, init_db

__version__ = "0.1.0"

__all__ = [
    "AuthConfig",
    "get_config",
    "setup_auth",
    "__version__",
]


def setup_auth(
    app: FastAPI,
    config: AuthConfig | None = None,
    *,
    prefix: str | None = None,
) -> None:
    """Initialise le module d'authentification sur une application FastAPI.

    Args:
        app: L'application FastAPI cible.
        config: Configuration optionnelle. Si None, utilise les variables
                d'environnement avec le préfixe AUTH_.
        prefix: Préfixe des routes. Si None, utilise config.api_prefix.
    """
    cfg = config or get_config()
    api_prefix = prefix or cfg.api_prefix

    # Stocker la config dans l'état de l'app
    app.state.auth_config = cfg

    # Initialiser la DB
    init_db(cfg)

    # Ajouter une route de santé pour vérifier que le module est bien monté
    @app.get(f"{api_prefix}/health", tags=["auth"])
    async def auth_health() -> dict:
        return {"status": "ok", "module": "auth-backend", "version": __version__}
