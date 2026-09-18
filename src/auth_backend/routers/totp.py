"""Endpoints TOTP."""
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import AuthConfig
from ..database import get_db
from ..dependencies import get_auth_config, get_current_user
from ..models import User
from ..schemas import (
    TOTPDisableRequest,
    TOTPRecoveryRequest,
    TOTPSetupResponse,
    TOTPStatusResponse,
    TOTPVerifyRequest,
    TOTPVerifyResponse,
)
from ..services import totp_service

router = APIRouter(prefix="/totp", tags=["totp"])


@router.post(
    "/setup",
    response_model=TOTPSetupResponse,
    summary="Démarrer l'enrôlement TOTP",
)
async def setup(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(get_auth_config),
) -> TOTPSetupResponse:
    """Génère un secret TOTP et retourne le QR code à scanner."""
    result = await totp_service.start_setup(db, current_user, config)
    return TOTPSetupResponse(**result)


@router.post(
    "/verify",
    response_model=TOTPVerifyResponse,
    summary="Vérifier et activer le TOTP",
)
async def verify(
    data: TOTPVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(get_auth_config),
) -> TOTPVerifyResponse:
    """Vérifie un premier code TOTP et active le 2FA.

    Retourne les codes de secours — à conserver par l'utilisateur.
    """
    recovery_codes = await totp_service.verify_and_enable(
        db, current_user, data.code, config
    )
    return TOTPVerifyResponse(
        success=True,
        message="TOTP activé. Conservez vos codes de secours en lieu sûr.",
        recovery_codes=recovery_codes,
    )


@router.post(
    "/disable",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Désactiver le TOTP",
)
async def disable(
    data: TOTPDisableRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(get_auth_config),
) -> None:
    """Désactive le TOTP après vérification d'un code valide."""
    await totp_service.disable(db, current_user, data.code, config)


@router.get(
    "/status",
    response_model=TOTPStatusResponse,
    summary="Statut du TOTP",
)
async def status_endpoint(
    current_user: User = Depends(get_current_user),
) -> TOTPStatusResponse:
    """Retourne l'état du TOTP pour l'utilisateur connecté."""
    return TOTPStatusResponse(**totp_service.get_status(current_user))


@router.post(
    "/recovery",
    response_model=TOTPVerifyResponse,
    summary="Utiliser un code de secours",
)
async def recovery(
    data: TOTPRecoveryRequest,
    db: AsyncSession = Depends(get_db),
) -> TOTPVerifyResponse:
    """Valide un code de secours (endpoint public).

    Le code est invalidé après usage. L'application cliente peut
    ensuite déclencher un flux de connexion (par exemple, rediriger
    vers la page de connexion avec un token court).
    """
    await totp_service.use_recovery_code(db, data.email, data.recovery_code)
    return TOTPVerifyResponse(
        success=True,
        message="Code de secours accepté. Vous pouvez vous reconnecter.",
    )
