"""Module d'authentification réutilisable pour FastAPI."""
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
    """Initialise le module d'authentification sur une application FastAPI."""
    cfg = config or get_config()
    api_prefix = prefix or cfg.api_prefix

    app.state.auth_config = cfg
    init_db(cfg)

    # === Routers ===
 
    
    
    from .routers import (
        auth as auth_router,
        otp as otp_router,
        passkeys as passkeys_router,
        totp as totp_router,
    )
    app.include_router(auth_router.router, prefix=api_prefix)
    app.include_router(otp_router.router, prefix=api_prefix)
    app.include_router(totp_router.router, prefix=api_prefix)
    app.include_router(passkeys_router.router, prefix=api_prefix)
    

    # === Route de santé ===
    @app.get(f"{api_prefix}/health", tags=["auth"])
    async def auth_health() -> dict:
        return {"status": "ok", "module": "auth-backend", "version": __version__}
        
        
        
    