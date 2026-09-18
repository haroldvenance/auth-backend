"""Tests du back-office admin pour la vérification d'identité."""
import io

import pytest
from PIL import Image


REGISTER_DATA = {
    "email": "kycadmin@example.com",
    "display_name": "KYC Admin User",
    "password": "MotDePasse123!",
}


def _make_test_image() -> bytes:
    img = Image.new("RGB", (100, 100), color="green")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()


async def _register_and_login(client) -> str:
    await client.post("/api/v1/auth/register", json=REGISTER_DATA)
    login = await client.post(
        "/api/v1/auth/token",
        data={"username": "kycadmin@example.com", "password": "MotDePasse123!"},
    )
    return login.json()["access_token"]


async def _submit_verification(client, token, doc_number="ADMIN123") -> str:
    """Soumet une vérification et retourne l'ID de la demande."""
    image = _make_test_image()
    response = await client.post(
        "/api/v1/auth/verification/submit",
        headers={"Authorization": f"Bearer {token}"},
        data={
            "full_name": "Jean Test",
            "document_type": "cni",
            "document_number": doc_number,
        },
        files={
            "selfie": ("selfie.png", image, "image/png"),
            "document_front": ("front.png", image, "image/png"),
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


# ============================================================
# Sécurité : accès refusé aux non-admins
# ============================================================
@pytest.mark.asyncio
async def test_admin_list_requires_auth(client):
    response = await client.get("/api/v1/auth/admin/verifications")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_admin_list_forbidden_for_non_admin(client):
    token = await _register_and_login(client)
    response = await client.get(
        "/api/v1/auth/admin/verifications",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


# ============================================================
# Liste
# ============================================================
@pytest.mark.asyncio
async def test_admin_list_empty(admin_client):
    response = await admin_client.get("/api/v1/auth/admin/verifications")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert data["items"] == []


@pytest.mark.asyncio
async def test_admin_list_with_pending(client, admin_client):
    token = await _register_and_login(client)
    await _submit_verification(client, token)

    response = await admin_client.get(
        "/api/v1/auth/admin/verifications?status=pending"
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["status"] == "pending"
    assert data["items"][0]["full_name"] == "Jean Test"


# ============================================================
# Détails
# ============================================================
@pytest.mark.asyncio
async def test_admin_get_detail(admin_client, client):
    token = await _register_and_login(client)
    request_id = await _submit_verification(client, token)

    response = await admin_client.get(
        f"/api/v1/auth/admin/verifications/{request_id}"
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "pending"
    assert data["full_name"] == "Jean Test"
    assert data["selfie_url"].startswith("/api/v1/auth/verification/file/")
    assert data["document_front_url"].startswith("/api/v1/auth/verification/file/")


@pytest.mark.asyncio
async def test_admin_get_detail_not_found(admin_client):
    response = await admin_client.get(
        "/api/v1/auth/admin/verifications/00000000-0000-0000-0000-000000000000"
    )
    assert response.status_code == 404


# ============================================================
# Approve
# ============================================================
@pytest.mark.asyncio
async def test_admin_approve(admin_client, client):
    token = await _register_and_login(client)
    request_id = await _submit_verification(client, token, doc_number="APPROVE1")

    response = await admin_client.post(
        f"/api/v1/auth/admin/verifications/{request_id}/approve"
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["status"] == "approved"

    # Le statut utilisateur a changé
    status_resp = await client.get(
        "/api/v1/auth/verification/status",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert status_resp.json()["is_verified"] is True
    assert status_resp.json()["status"] == "verified"


@pytest.mark.asyncio
async def test_admin_approve_twice_fails(admin_client, client):
    token = await _register_and_login(client)
    request_id = await _submit_verification(client, token, doc_number="APPROVE2")

    # Premier approve
    r1 = await admin_client.post(
        f"/api/v1/auth/admin/verifications/{request_id}/approve"
    )
    assert r1.status_code == 200

    # Second approve → échec
    r2 = await admin_client.post(
        f"/api/v1/auth/admin/verifications/{request_id}/approve"
    )
    assert r2.status_code == 400


# ============================================================
# Reject
# ============================================================
@pytest.mark.asyncio
async def test_admin_reject(admin_client, client):
    token = await _register_and_login(client)
    request_id = await _submit_verification(client, token, doc_number="REJECT1")

    response = await admin_client.post(
        f"/api/v1/auth/admin/verifications/{request_id}/reject",
        json={"reason": "Document illisible"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "rejected"

    # Statut utilisateur mis à jour
    status_resp = await client.get(
        "/api/v1/auth/verification/status",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert status_resp.json()["status"] == "rejected"
    assert status_resp.json()["is_verified"] is False


# ============================================================
# Stats
# ============================================================
@pytest.mark.asyncio
async def test_admin_stats(admin_client, client):
    token = await _register_and_login(client)
    req1 = await _submit_verification(client, token, doc_number="STATS1")

    # Approve la première
    await admin_client.post(
        f"/api/v1/auth/admin/verifications/{req1}/approve"
    )

    response = await admin_client.get("/api/v1/auth/admin/stats")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["approved"] == 1
    assert data["pending"] == 0
    assert data["rejected"] == 0
    assert data["approval_rate"] == 100.0
