"""Logique métier de la vérification d'identité."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import AuthConfig
from ..exceptions import (
    VerificationAdminActionError,
    VerificationAlreadyPendingError,
    VerificationAlreadyVerifiedError,
    VerificationDuplicateDocumentError,
    VerificationMaxAttemptsError,
    VerificationNotFoundError,
)



from ..models import User, VerificationRequest
from ..security import hash_document_number
from .storage_service import StorageService

from ..email.sender import EmailSender
from ..email.templates import (
    verification_approved_email,
    verification_rejected_email,
)

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




# ============================================================
# Admin
# ============================================================
async def list_requests(
    db: AsyncSession,
    *,
    status: str | None = None,
    page: int = 1,
    page_size: int = 20,
) -> dict:
    """Liste paginée des demandes de vérification (admin)."""
    from sqlalchemy import func

    page = max(1, page)
    page_size = min(max(1, page_size), 100)

    base_query = select(VerificationRequest)
    count_query = select(func.count(VerificationRequest.id))

    if status:
        base_query = base_query.where(VerificationRequest.status == status)
        count_query = count_query.where(VerificationRequest.status == status)

    # Total
    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    # Pagination
    offset = (page - 1) * page_size
    base_query = (
        base_query
        .order_by(VerificationRequest.created_at.asc())  # FIFO
        .offset(offset)
        .limit(page_size)
    )
    result = await db.execute(base_query)
    requests = list(result.scalars())

    # Charger les users associés
    from ..models import User
    items = []
    now = _utcnow()
    for req in requests:
        user = await db.get(User, req.user_id)
        waiting = (now - req.created_at).total_seconds() / 3600 if req.created_at else 0
        items.append({
            "id": req.id,
            "user_id": req.user_id,
            "user_email": user.email if user else None,
            "user_display_name": user.display_name if user else "?",
            "full_name": req.full_name,
            "document_type": req.document_type,
            "status": req.status,
            "created_at": req.created_at,
            "reviewed_at": req.reviewed_at,
            "waiting_hours": round(waiting, 1),
            "attempts": user.verification_attempts if user else 0,
        })

    total_pages = (total + page_size - 1) // page_size if total > 0 else 1

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


async def get_request_detail(
    db: AsyncSession,
    request_id: "UUID",
    config: AuthConfig,
) -> dict:
    """Détails d'une demande + URLs signées temporaires."""
    from uuid import UUID as UUIDType

    stmt = select(VerificationRequest).where(VerificationRequest.id == request_id)
    result = await db.execute(stmt)
    req = result.scalar_one_or_none()
    if not req:
        raise VerificationNotFoundError()

    user = await db.get(User, req.user_id)
    now = _utcnow()
    waiting = (now - req.created_at).total_seconds() / 3600 if req.created_at else 0

    # Générer des URLs signées (HMAC) valides 15 minutes
    selfie_url = _sign_file_url(req.selfie_path, config, ttl_seconds=900)
    front_url = _sign_file_url(req.document_front_path, config, ttl_seconds=900)
    back_url = (
        _sign_file_url(req.document_back_path, config, ttl_seconds=900)
        if req.document_back_path else None
    )

    return {
        "id": req.id,
        "user_id": req.user_id,
        "user_email": user.email if user else None,
        "user_display_name": user.display_name if user else "?",
        "user_created_at": user.created_at if user else now,
        "user_verified": user.is_verified if user else False,
        "full_name": req.full_name,
        "date_of_birth": req.date_of_birth,
        "document_type": req.document_type,
        "status": req.status,
        "rejection_reason": req.rejection_reason,
        "admin_notes": req.admin_notes,
        "selfie_url": selfie_url,
        "document_front_url": front_url,
        "document_back_url": back_url,
        "created_at": req.created_at,
        "reviewed_at": req.reviewed_at,
        "reviewed_by": req.reviewed_by,
        "waiting_hours": round(waiting, 1),
    }


def _sign_file_url(path: str, config: AuthConfig, ttl_seconds: int = 900) -> str:
    """Crée une URL signée temporaire pour accéder à un fichier chiffré.

    Le format est : /api/v1/auth/verification/file/{path}?exp={ts}&sig={hmac}
    L'admin doit fournir cette URL pour télécharger le fichier déchiffré.
    """
    import hashlib
    import hmac
    import time
    from urllib.parse import quote

    expires = int(time.time()) + ttl_seconds
    message = f"{path}:{expires}".encode()
    sig = hmac.new(
        config.secret_key.encode(),
        message,
        hashlib.sha256,
    ).hexdigest()
    return f"{config.api_prefix}/verification/file/{quote(path)}?exp={expires}&sig={sig}"


def verify_signed_url(
    path: str,
    exp: int,
    sig: str,
    config: AuthConfig,
) -> bool:
    """Vérifie une URL signée."""
    import hashlib
    import hmac
    import time

    if exp < int(time.time()):
        return False
    message = f"{path}:{exp}".encode()
    expected = hmac.new(
        config.secret_key.encode(),
        message,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, sig)


async def approve_request(
    db: AsyncSession,
    request_id: "UUID",
    admin: User,
    config: AuthConfig,
    admin_notes: str | None = None,
) -> VerificationRequest:
    """Approuve une demande et marque l'utilisateur comme vérifié."""
    stmt = select(VerificationRequest).where(VerificationRequest.id == request_id)
    result = await db.execute(stmt)
    req = result.scalar_one_or_none()
    if not req:
        raise VerificationNotFoundError()

    if req.status != "pending":
        raise VerificationAdminActionError(
            f"Cette demande est déjà '{req.status}'. "
            "Seules les demandes 'pending' peuvent être traitées."
        )

    req.status = "approved"
    req.reviewed_by = admin.id
    req.reviewed_at = _utcnow()
    if admin_notes:
        req.admin_notes = admin_notes

    # Mettre à jour l'utilisateur
    user = await db.get(User, req.user_id)
    if user:
        user.is_verified = True
        user.verification_status = "verified"
        user.verified_at = _utcnow()
        user.updated_at = _utcnow()

    await db.commit()
    await db.refresh(req)

    # Notification par email (best effort)
    if user and user.email:
        try:
            subject, body_text, body_html = verification_approved_email(
                display_name=user.display_name,
                app_name=config.totp_issuer,
            )
            sender = EmailSender(config)
            await sender.send(
                to=user.email,
                subject=subject,
                body_text=body_text,
                body_html=body_html,
            )
        except Exception as exc:
            logger.error("Échec envoi notification approbation à %s : %s",
                         user.email, exc)

    return req





async def reject_request(
    db: AsyncSession,
    request_id: "UUID",
    admin: User,
    reason: str,
    config: AuthConfig,
    admin_notes: str | None = None,
) -> VerificationRequest:
    """Rejette une demande avec un motif."""
    stmt = select(VerificationRequest).where(VerificationRequest.id == request_id)
    result = await db.execute(stmt)
    req = result.scalar_one_or_none()
    if not req:
        raise VerificationNotFoundError()

    if req.status != "pending":
        raise VerificationAdminActionError(
            f"Cette demande est déjà '{req.status}'."
        )

    req.status = "rejected"
    req.rejection_reason = reason
    req.reviewed_by = admin.id
    req.reviewed_at = _utcnow()
    if admin_notes:
        req.admin_notes = admin_notes

    # Mettre à jour l'utilisateur
    user = await db.get(User, req.user_id)
    attempts_remaining = 0
    if user:
        user.verification_status = "rejected"
        user.updated_at = _utcnow()
        attempts_remaining = max(0, config.verification_max_attempts - user.verification_attempts)

    await db.commit()
    await db.refresh(req)

    # Notification par email (best effort)
    if user and user.email:
        try:
            subject, body_text, body_html = verification_rejected_email(
                display_name=user.display_name,
                reason=reason,
                attempts_remaining=attempts_remaining,
                app_name=config.totp_issuer,
            )
            sender = EmailSender(config)
            await sender.send(
                to=user.email,
                subject=subject,
                body_text=body_text,
                body_html=body_html,
            )
        except Exception as exc:
            logger.error("Échec envoi notification rejet à %s : %s",
                         user.email, exc)

    return req
    
    
    
   


async def get_stats(db: AsyncSession) -> dict:
    """Statistiques globales du back-office."""
    from sqlalchemy import func

    # Compteurs par statut
    statuses = ["pending", "approved", "rejected"]
    counts = {}
    for s in statuses:
        stmt = select(func.count(VerificationRequest.id)).where(
            VerificationRequest.status == s
        )
        result = await db.execute(stmt)
        counts[s] = result.scalar_one()

    total = sum(counts.values())

    # Taux d'approbation (parmi les traitées)
    treated = counts["approved"] + counts["rejected"]
    approval_rate = (counts["approved"] / treated * 100) if treated > 0 else 0.0

    # Temps d'attente moyen des pending
    stmt_wait = select(VerificationRequest.created_at).where(
        VerificationRequest.status == "pending"
    )
    result_wait = await db.execute(stmt_wait)
    now = _utcnow()
    waits = [
        (now - row).total_seconds() / 3600
        for row in result_wait.scalars()
        if row
    ]
    avg_wait = sum(waits) / len(waits) if waits else 0.0

    # Top 5 des motifs de rejet
    stmt_reasons = (
        select(
            VerificationRequest.rejection_reason,
            func.count(VerificationRequest.id).label("count"),
        )
        .where(VerificationRequest.status == "rejected")
        .where(VerificationRequest.rejection_reason.isnot(None))
        .group_by(VerificationRequest.rejection_reason)
        .order_by(func.count(VerificationRequest.id).desc())
        .limit(5)
    )
    result_reasons = await db.execute(stmt_reasons)
    top_reasons = [
        {"reason": row[0], "count": row[1]}
        for row in result_reasons.all()
    ]

    return {
        "total": total,
        "pending": counts["pending"],
        "approved": counts["approved"],
        "rejected": counts["rejected"],
        "approval_rate": round(approval_rate, 1),
        "average_wait_hours": round(avg_wait, 1),
        "rejection_reasons_top": top_reasons,
    }
    
    
    
    
    
# ============================================================
# Nettoyage
# ============================================================
async def cleanup_expired_documents(
    db: AsyncSession,
    config: AuthConfig,
    *,
    dry_run: bool = False,
) -> dict:
    """Supprime les documents de vérification plus vieux que la rétention.

    Supprime les fichiers chiffrés (selfie, document_front, document_back)
    pour toutes les demandes dont `reviewed_at` est plus ancien que
    `config.verification_retention_days`. Les enregistrements en DB sont
    conservés (seuls les chemins sont effacés).

    Args:
        dry_run: si True, ne supprime rien mais liste ce qui serait supprimé.
    """
    retention_days = config.verification_retention_days
    cutoff = _utcnow() - timedelta(days=retention_days)

    stmt = select(VerificationRequest).where(
        VerificationRequest.reviewed_at.isnot(None),
        VerificationRequest.reviewed_at < cutoff,
        VerificationRequest.selfie_path != "",
    )
    result = await db.execute(stmt)
    requests = list(result.scalars())

    storage = StorageService(config)
    deleted_files = 0
    errors = 0
    cleaned_ids: list[str] = []

    for req in requests:
        paths = [
            req.selfie_path,
            req.document_front_path,
            req.document_back_path,
        ]
        for path in paths:
            if not path:
                continue
            if dry_run:
                deleted_files += 1
                continue
            try:
                storage.delete_file(path)
                deleted_files += 1
            except Exception as exc:
                logger.warning("Échec suppression %s : %s", path, exc)
                errors += 1

        if not dry_run:
            # Effacer les chemins en DB pour éviter de retenter
            req.selfie_path = ""
            req.document_front_path = ""
            req.document_back_path = None
            cleaned_ids.append(str(req.id))

    if not dry_run:
        await db.commit()

    return {
        "requests_cleaned": len(cleaned_ids) if not dry_run else len(requests),
        "files_deleted": deleted_files,
        "errors": errors,
        "retention_days": retention_days,
        "dry_run": dry_run,
        "request_ids": cleaned_ids,
    }