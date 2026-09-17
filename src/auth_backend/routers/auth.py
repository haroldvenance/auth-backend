"""Endpoints d'authentification de base."""
from fastapi import APIRouter, Depends, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import AuthConfig
from ..database import get_db
from ..dependencies import get_auth_config, get_current_user
from ..models import User
from ..schemas import (
    RefreshRequest,
    RefreshResponse,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from ..services import auth_service

router = APIRouter(tags=["auth"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Inscription",
)
async def register(
    data: RegisterRequest,
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(get_auth_config),
) -> User:
    """Crée un nouveau compte utilisateur (non vérifié)."""
    return await auth_service.register_user(db, data, config)


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Connexion (OAuth2 password flow)",
)
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(get_auth_config),
) -> TokenResponse:
    """Authentifie un utilisateur et retourne access + refresh tokens."""
    user = await auth_service.authenticate_user(
        db, form_data.username, form_data.password
    )

    user_agent = request.headers.get("user-agent")
    ip_address = request.client.host if request.client else None

    return await auth_service.create_tokens_for_user(
        db, user, config,
        user_agent=user_agent,
        ip_address=ip_address,
    )


@router.post(
    "/refresh",
    response_model=RefreshResponse,
    summary="Rafraîchir l'access token",
)
async def refresh(
    data: RefreshRequest,
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(get_auth_config),
) -> RefreshResponse:
    new_access, expires_in = await auth_service.refresh_access_token(
        db, data.refresh_token, config
    )
    return RefreshResponse(access_token=new_access, expires_in=expires_in)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Déconnexion",
)
async def logout(
    data: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> None:
    await auth_service.revoke_refresh_token(db, data.refresh_token)


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Profil de l'utilisateur connecté",
)
async def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user
