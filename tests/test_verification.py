"""Tests du flux de vérification d'identité (soumission)."""
import io

import pytest
from PIL import Image


REGISTER_DATA = {
    "email": "kyc@example.com",
    "display_name": "KYC User",
    "password": "MotDePasse123!",
}


def _make_test_image() -> bytes:
    """Génère une petite image PNG en mémoire."""
    img = Image.new("RGB", (100, 100), color="red")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()


async def _register_and_login(client) -> str:
    await client.post("/api/v1/auth/register", json=REGISTER_DATA)
    login = await client.post(
        "/api/v1/auth/token",
        data={"username": "kyc@example.com", "password": "MotDePasse123!"},
    )
    return login.json()["access_token"]


@pytest.mark.asyncio
async def test_status_initially_unverified(client):
    token = await _register_and_login(client)
    response = await client.get(
        "/api/v1/auth/verification/status",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "unverified"
    assert data["is_verified"] is False
    assert data["attempts"] == 0
    assert data["latest_request"] is None


@pytest.mark.asyncio
async def test_submit_requires_auth(client):
    response = await client.post("/api/v1/auth/verification/submit")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_submit_success(client):
    token = await _register_and_login(client)
    image_bytes = _make_test_image()

    response = await client.post(
        "/api/v1/auth/verification/submit",
        headers={"Authorization": f"Bearer {token}"},
        data={
            "full_name": "Jean Dupont",
            "document_type": "cni",
            "document_number": "CNI123456",
        },
        files={
            "selfie": ("selfie.png", image_bytes, "image/png"),
            "document_front": ("front.png", image_bytes, "image/png"),
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["full_name"] == "Jean Dupont"
    assert data["document_type"] == "cni"
    assert data["status"] == "pending"

    # Statut mis à jour
    status_resp = await client.get(
        "/api/v1/auth/verification/status",
        headers={"Authorization": f"Bearer {token}"},
    )
    status_data = status_resp.json()
    assert status_data["status"] == "pending"
    assert status_data["attempts"] == 1
    assert status_data["latest_request"]["status"] == "pending"


@pytest.mark.asyncio
async def test_submit_twice_pending_fails(client):
    token = await _register_and_login(client)
    image_bytes = _make_test_image()

    payload = {
        "full_name": "Jean Dupont",
        "document_type": "cni",
        "document_number": "CNI123456",
    }
    files = {
        "selfie": ("selfie.png", image_bytes, "image/png"),
        "document_front": ("front.png", image_bytes, "image/png"),
    }

    # Premier submit
    r1 = await client.post(
        "/api/v1/auth/verification/submit",
        headers={"Authorization": f"Bearer {token}"},
        data=payload,
        files=files,
    )
    assert r1.status_code == 201

    # Second submit → doit échouer
    r2 = await client.post(
        "/api/v1/auth/verification/submit",
        headers={"Authorization": f"Bearer {token}"},
        data=payload,
        files=files,
    )
    assert r2.status_code == 409


@pytest.mark.asyncio
async def test_submit_duplicate_document_fails(client, db_session):
    """Un document déjà approuvé pour un autre compte est refusé."""
    from datetime import datetime, timezone
    from auth_backend.models import User, VerificationRequest
    from auth_backend.security import hash_document_number

    # Créer un user + une demande approuvée manuellement
    doc_hash = hash_document_number("CNI999999")

    # User 1 approuvé
    user1 = User(
        email="user1@example.com",
        display_name="User 1",
        is_active=True,
        is_verified=True,
        verification_status="verified",
    )
    db_session.add(user1)
    await db_session.commit()
    await db_session.refresh(user1)

    req1 = VerificationRequest(
        user_id=user1.id,
        full_name="User 1",
        document_type="cni",
        document_number_hash=doc_hash,
        selfie_path="x",
        document_front_path="y",
        status="approved",
        reviewed_at=datetime.now(timezone.utc),
    )
    db_session.add(req1)
    await db_session.commit()

    # User 2 tente de soumettre le même document
    token = await _register_and_login(client)
    image_bytes = _make_test_image()

    response = await client.post(
        "/api/v1/auth/verification/submit",
        headers={"Authorization": f"Bearer {token}"},
        data={
            "full_name": "User 2",
            "document_type": "cni",
            "document_number": "CNI999999",
        },
        files={
            "selfie": ("selfie.png", image_bytes, "image/png"),
            "document_front": ("front.png", image_bytes, "image/png"),
        },
    )
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_submit_invalid_document_type(client):
    token = await _register_and_login(client)
    image_bytes = _make_test_image()

    response = await client.post(
        "/api/v1/auth/verification/submit",
        headers={"Authorization": f"Bearer {token}"},
        data={
            "full_name": "Jean Dupont",
            "document_type": "invalid_type",
            "document_number": "CNI123",
        },
        files={
            "selfie": ("selfie.png", image_bytes, "image/png"),
            "document_front": ("front.png", image_bytes, "image/png"),
        },
    )
    assert response.status_code == 415
