"""Endpoints de vérification d'identité (côté utilisateur)."""
from datetime import datetime

from fastapi import APIRouter, Depends, File, Form, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import AuthConfig
from ..database import get_db
from ..dependencies import get_auth_config, get_current_user
from ..exceptions import VerificationInvalidFileTypeError
from ..models import User
from ..schemas import (
    VerificationRequestResponse,
    VerificationStatusResponse,
)
from ..services import verification_service

router = APIRouter(prefix="/verification", tags=["verification"])


DOCUMENT_TYPES = {
    "cni",
    "passport",
    "student_card",
    "school_card",
    "livret",
    "driver_license",
    "other",
}


@router.post(
    "/submit",
    response_model=VerificationRequestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Soumettre une demande de vérification",
)
async def submit(
    full_name: str = Form(..., min_length=2, max_length=150),
    document_type: str = Form(...),
    document_number: str = Form(..., min_length=2, max_length=100),
    date_of_birth: str | None = Form(default=None),
    selfie: UploadFile = File(..., description="Selfie en direct"),
    document_front: UploadFile = File(..., description="Recto du document"),
    document_back: UploadFile | None = File(default=None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(get_auth_config),
) -> VerificationRequestResponse:
    """Soumet une demande de vérification d'identité.

    Le selfie doit être pris en direct (caméra frontale).
    Le document peut être une CNI, un passeport, une carte d'étudiant, etc.
    """
    if document_type not in DOCUMENT_TYPES:
        raise VerificationInvalidFileTypeError()

    # Lire le contenu des fichiers
    selfie_content = await selfie.read()
    doc_front_content = await document_front.read()
    doc_back_content = await document_back.read() if document_back else None

    # Parser la date de naissance si fournie
    parsed_dob = None
    if date_of_birth:
        try:
            parsed_dob = datetime.fromisoformat(date_of_birth)
        except ValueError:
            parsed_dob = None

    request = await verification_service.submit(
        db,
        current_user,
        config,
        full_name=full_name,
        document_type=document_type,
        document_number=document_number,
        date_of_birth=parsed_dob,
        selfie_content=selfie_content,
        selfie_content_type=selfie.content_type,
        document_front_content=doc_front_content,
        document_front_content_type=document_front.content_type,
        document_back_content=doc_back_content,
        document_back_content_type=document_back.content_type if document_back else None,
    )
    return VerificationRequestResponse.model_validate(request)


@router.get(
    "/status",
    response_model=VerificationStatusResponse,
    summary="Statut de ma vérification",
)
async def get_status(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> VerificationStatusResponse:
    """Retourne le statut de vérification de l'utilisateur connecté."""
    data = await verification_service.get_status(db, current_user)
    return VerificationStatusResponse(**data)


@router.post(
    "/resubmit",
    response_model=VerificationRequestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Resoumettre une demande après rejet",
)
async def resubmit(
    full_name: str = Form(..., min_length=2, max_length=150),
    document_type: str = Form(...),
    document_number: str = Form(..., min_length=2, max_length=100),
    date_of_birth: str | None = Form(default=None),
    selfie: UploadFile = File(...),
    document_front: UploadFile = File(...),
    document_back: UploadFile | None = File(default=None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    config: AuthConfig = Depends(get_auth_config),
) -> VerificationRequestResponse:
    """Resoumet une demande après un rejet (max 3 tentatives au total)."""
    if document_type not in DOCUMENT_TYPES:
        raise VerificationInvalidFileTypeError()

    selfie_content = await selfie.read()
    doc_front_content = await document_front.read()
    doc_back_content = await document_back.read() if document_back else None

    parsed_dob = None
    if date_of_birth:
        try:
            parsed_dob = datetime.fromisoformat(date_of_birth)
        except ValueError:
            parsed_dob = None

    request = await verification_service.resubmit(
        db,
        current_user,
        config,
        full_name=full_name,
        document_type=document_type,
        document_number=document_number,
        date_of_birth=parsed_dob,
        selfie_content=selfie_content,
        selfie_content_type=selfie.content_type,
        document_front_content=doc_front_content,
        document_front_content_type=document_front.content_type,
        document_back_content=doc_back_content,
        document_back_content_type=document_back.content_type if document_back else None,
    )
    return VerificationRequestResponse.model_validate(request)
