"""Logique métier de la vérification d'identité."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import AuthConfig
from ..exceptions import (
    VerificationAlreadyPendingError,
    VerificationAlreadyVerifiedError,
    VerificationDuplicateDocumentError,
    VerificationMaxAttemptsError,
    VerificationNotFoundError,
)
from ..models import User, VerificationRequest
from ..security import hash_document_number
from .storage_service import StorageService

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def submit(
    db: AsyncSession,
    user: User,
    config: AuthConfig,
    *,
    full_name: str,
    document_type: str,
    document_number: str,
    selfie_content: bytes,
    document_front_content: bytes,
    document_back_content: bytes | None = None,
    selfie_content_type: str | None = None,
    document_front_content_type: str | None = None,
    document_back_content_type: str | None = None,
    date_of_birth: datetime | None = None,
) -> VerificationRequest:
    """Soumet une demande de vérification.

    Raises:
        VerificationAlreadyVerifiedError, VerificationAlreadyPendingError,
        VerificationMaxAttemptsError, VerificationDuplicateDocumentError
    """
    # Déjà vérifié ?
    if user.is_verified:
        raise VerificationAlreadyVerifiedError()

    # Demande déjà en cours ?
    stmt_pending = select(VerificationRequest).where(
        VerificationRequest.user_id == user.id,
        VerificationRequest.status == "pending",
    )
    result_pending = await db.execute(stmt_pending)
    if result_pending.scalar_one_or_none():
        raise VerificationAlreadyPendingError()

    # Limite de tentatives
    if user.verification_attempts >= config.verification_max_attempts:
        raise VerificationMaxAttemptsError()

    # Détection de doublons (hash du numéro de document)
    doc_hash = hash_document_number(document_number)
    stmt_dup = select(VerificationRequest).where(
        VerificationRequest.document_number_hash == doc_hash,
        VerificationRequest.status == "approved",
    )
    result_dup = await db.execute(stmt_dup)
    if result_dup.scalar_one_or_none():
        raise VerificationDuplicateDocumentError()

    # Stocker les fichiers chiffrés
    storage = StorageService(config)

    selfie_path = storage.save_file(
        content=selfie_content,
        content_type=selfie_content_type,
        prefix="selfie",
    )
    doc_front_path = storage.save_file(
        content=document_front_content,
        content_type=document_front_content_type,
        prefix="doc_front",
    )
    doc_back_path = None
    if document_back_content:
        doc_back_path = storage.save_file(
            content=document_back_content,
            content_type=document_back_content_type,
            prefix="doc_back",
        )

    # Créer la demande
    request = VerificationRequest(
        user_id=user.id,
        full_name=full_name,
        date_of_birth=date_of_birth,
        document_type=document_type,
        document_number_hash=doc_hash,
        selfie_path=selfie_path,
        document_front_path=doc_front_path,
        document_back_path=doc_back_path,
        status="pending",
    )
    db.add(request)

    # Mettre à jour le statut de l'utilisateur
    user.verification_status = "pending"
    user.verification_attempts += 1
    user.updated_at = _utcnow()

    await db.commit()
    await db.refresh(request)
    await db.refresh(user)
    return request


async def get_status(
    db: AsyncSession,
    user: User,
) -> dict:
    """Retourne le statut de vérification de l'utilisateur."""
    # Chercher la dernière demande
    stmt = (
        select(VerificationRequest)
        .where(VerificationRequest.user_id == user.id)
        .order_by(VerificationRequest.created_at.desc())
        .limit(1)
    )
    result = await db.execute(stmt)
    latest = result.scalar_one_or_none()

    return {
        "status": user.verification_status,
        "is_verified": user.is_verified,
        "attempts": user.verification_attempts,
        "max_attempts": 3,
        "latest_request": {
            "id": str(latest.id),
            "status": latest.status,
            "document_type": latest.document_type,
            "created_at": latest.created_at.isoformat(),
            "reviewed_at": latest.reviewed_at.isoformat() if latest.reviewed_at else None,
            "rejection_reason": latest.rejection_reason,
        } if latest else None,
    }


async def resubmit(
    db: AsyncSession,
    user: User,
    config: AuthConfig,
    **kwargs,
) -> VerificationRequest:
    """Resoumet une demande après un rejet.

    Supprime les anciens fichiers et crée une nouvelle demande.
    """
    # Vérifier qu'il y a eu un rejet
    stmt = (
        select(VerificationRequest)
        .where(
            VerificationRequest.user_id == user.id,
            VerificationRequest.status == "rejected",
        )
        .order_by(VerificationRequest.created_at.desc())
        .limit(1)
    )
    result = await db.execute(stmt)
    latest_rejected = result.scalar_one_or_none()
    if not latest_rejected:
        raise VerificationNotFoundError("Aucune demande rejetée à resoumettre.")

    # Supprimer les anciens fichiers
    storage = StorageService(config)
    paths_to_delete = [
        latest_rejected.selfie_path,
        latest_rejected.document_front_path,
    ]
    if latest_rejected.document_back_path:
        paths_to_delete.append(latest_rejected.document_back_path)
    storage.delete_many(paths_to_delete)

    # Créer une nouvelle demande (le compteur de tentatives est déjà incrémenté)
    return await submit(db, user, config, **kwargs)
