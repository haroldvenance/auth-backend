"""Endpoints d'administration."""
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import AuthConfig
from ..database import get_db
from ..dependencies import get_auth_config, require_admin
from ..models import User
from ..schemas import (
    VerificationActionResponse,
    VerificationAdminDetailResponse,
    VerificationAdminListResponse,
    VerificationRejectRequest,
    VerificationStatsResponse,
)
from ..services import verification_service

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get(
    "/verifications",
    response_model=VerificationAdminListResponse,
    summary="File d'attente des vérifications",
)
async def list_verifications(
    status_filter: str | None = Query(default=None, alias="status"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> VerificationAdminListResponse:
    """Liste paginée des demandes (par défaut : toutes)."""
    data = await verification_service.list_requests(
        db, status=status_filter, page=page, page_size=page_size
    )
    return VerificationAdminListResponse(**data)


@router.get(
    "/verifications/{request_id}",
    response_model=VerificationAdminDetailResponse,
    summary="Détails d'une demande",
)
async def get_verification(
    request_id: UUID,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(get_auth_config),
) -> VerificationAdminDetailResponse:
    """Détails complets + URLs signées pour visualiser les documents."""
    data = await verification_service.get_request_detail(db, request_id, config)
    return VerificationAdminDetailResponse(**data)


@router.post(
    "/verifications/{request_id}/approve",
    response_model=VerificationActionResponse,
    summary="Approuver une vérification",
)
async def approve_verification(
    request_id: UUID,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> VerificationActionResponse:
    """Approuve la demande et marque l'utilisateur comme vérifié."""
    req = await verification_service.approve_request(db, request_id, admin)
    return VerificationActionResponse(
        success=True,
        message="Demande approuvée.",
        request_id=req.id,
        status=req.status,
    )


@router.post(
    "/verifications/{request_id}/reject",
    response_model=VerificationActionResponse,
    summary="Rejeter une vérification",
)
async def reject_verification(
    request_id: UUID,
    data: VerificationRejectRequest,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> VerificationActionResponse:
    """Rejette la demande avec un motif."""
    req = await verification_service.reject_request(
        db, request_id, admin, reason=data.reason, admin_notes=data.admin_notes
    )
    return VerificationActionResponse(
        success=True,
        message="Demande rejetée.",
        request_id=req.id,
        status=req.status,
    )


@router.get(
    "/stats",
    response_model=VerificationStatsResponse,
    summary="Statistiques du back-office",
)
async def get_stats(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> VerificationStatsResponse:
    """Statistiques globales (compteurs, taux, délais)."""
    data = await verification_service.get_stats(db)
    return VerificationStatsResponse(**data)
