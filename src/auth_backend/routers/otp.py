"""Endpoints OTP."""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import AuthConfig
from ..database import get_db
from ..dependencies import get_auth_config
from ..schemas import OTPRequest, OTPResponse, OTPVerifyRequest
from ..services import otp_service

router = APIRouter(prefix="/otp", tags=["otp"])


@router.post(
    "/request",
    response_model=OTPResponse,
    summary="Demander un code OTP par email",
)
async def request_otp(
    data: OTPRequest,
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(get_auth_config),
) -> OTPResponse:
    """Envoie un code OTP à l'email indiqué.

    Pour des raisons de sécurité, la réponse est toujours positive
    (que l'email existe ou non) pour éviter l'énumération de comptes.
    """
    await otp_service.request_otp(db, config, data.email, data.purpose)
    return OTPResponse(
        success=True,
        message="Si cet email est valide, un code vous a été envoyé.",
    )


@router.post(
    "/verify",
    response_model=OTPResponse,
    summary="Vérifier un code OTP",
)
async def verify_otp(
    data: OTPVerifyRequest,
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(get_auth_config),
) -> OTPResponse:
    """Vérifie un code OTP."""
    await otp_service.verify_otp(db, config, data.email, data.code, data.purpose)
    return OTPResponse(success=True, message="Code vérifié avec succès.")
