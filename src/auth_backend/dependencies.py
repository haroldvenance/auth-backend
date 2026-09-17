"""Dépendances FastAPI réutilisables."""
from uuid import UUID

from fastapi import Depends, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from .config import AuthConfig
from .database import get_db
from .exceptions import (
    AdminRequiredError,
    InactiveUserError,
    InvalidTokenError,
    UnverifiedUserError,
)
from .models import User
from .security import decode_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/token", auto_error=False)


def get_auth_config(request: Request) -> AuthConfig:
    config = getattr(request.app.state, "auth_config", None)
    if config is None:
        raise RuntimeError(
            "Le module auth_backend n'est pas initialisé. "
            "Appelez setup_auth(app, config) au démarrage."
        )
    return config


async def get_current_user(
    token: str | None = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(get_auth_config),
) -> User:
    if not token:
        raise InvalidTokenError("Token d'authentification manquant")

    payload = decode_token(token, config, expected_type="access")
    user_id_str = payload.get("sub")
    if not user_id_str:
        raise InvalidTokenError("Token sans sujet")

    user = await db.get(User, UUID(user_id_str))
    if not user:
        raise InvalidTokenError("Utilisateur introuvable")

    if not user.is_active:
        raise InactiveUserError()

    return user


async def require_verified(
    current_user: User = Depends(get_current_user),
) -> User:
    if not current_user.is_verified:
        raise UnverifiedUserError()
    return current_user


async def require_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    if not current_user.is_admin:
        raise AdminRequiredError()
    return current_user
