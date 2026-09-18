"""Endpoints Passkeys (WebAuthn)."""
from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import AuthConfig
from ..database import get_db
from ..dependencies import get_auth_config, get_current_user
from ..models import User
from ..schemas import (
    AuthenticationBeginRequest,
    AuthenticationBeginResponse,
    AuthenticationFinishRequest,
    AuthenticationFinishResponse,
    PasskeyRenameRequest,
    PasskeyResponse,
    RegistrationBeginResponse,
    RegistrationFinishRequest,
)
from ..services import auth_service, passkey_service

router = APIRouter(prefix="/passkeys", tags=["passkeys"])


@router.post(
    "/register/begin",
    response_model=RegistrationBeginResponse,
    summary="Démarrer l'enregistrement d'une passkey",
)
async def register_begin(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(get_auth_config),
) -> RegistrationBeginResponse:
    options = await passkey_service.begin_registration(db, current_user, config)
    return RegistrationBeginResponse(options=options)


@router.post(
    "/register/finish",
    response_model=PasskeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Finaliser l'enregistrement d'une passkey",
)
async def register_finish(
    data: RegistrationFinishRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(get_auth_config),
) -> PasskeyResponse:
    passkey = await passkey_service.finish_registration(
        db, current_user, data.credential, data.device_name, config
    )
    return PasskeyResponse.model_validate(passkey)


@router.post(
    "/authenticate/begin",
    response_model=AuthenticationBeginResponse,
    summary="Démarrer la connexion par passkey",
)
async def authenticate_begin(
    data: AuthenticationBeginRequest,
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(get_auth_config),
) -> AuthenticationBeginResponse:
    options = await passkey_service.begin_authentication(
        db, config, email=data.email
    )
    return AuthenticationBeginResponse(options=options)


@router.post(
    "/authenticate/finish",
    response_model=AuthenticationFinishResponse,
    summary="Finaliser la connexion par passkey",
)
async def authenticate_finish(
    data: AuthenticationFinishRequest,
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(get_auth_config),
) -> AuthenticationFinishResponse:
    user = await passkey_service.finish_authentication(db, data.credential, config)
    tokens = await auth_service.create_tokens_for_user(db, user, config)
    return AuthenticationFinishResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        token_type=tokens.token_type,
        expires_in=tokens.expires_in,
        user=user,
    )


@router.get(
    "",
    response_model=list[PasskeyResponse],
    summary="Lister mes passkeys",
)
async def list_passkeys(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[PasskeyResponse]:
    passkeys = await passkey_service.list_passkeys(db, current_user)
    return [PasskeyResponse.model_validate(p) for p in passkeys]


@router.delete(
    "/{passkey_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Supprimer une passkey",
)
async def delete_passkey(
    passkey_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    await passkey_service.delete_passkey(db, current_user, passkey_id)


@router.patch(
    "/{passkey_id}",
    response_model=PasskeyResponse,
    summary="Renommer une passkey",
)
async def rename_passkey(
    passkey_id: UUID,
    data: PasskeyRenameRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> PasskeyResponse:
    passkey = await passkey_service.rename_passkey(
        db, current_user, passkey_id, data.device_name
    )
    return PasskeyResponse.model_validate(passkey)
