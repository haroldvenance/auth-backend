"""Tests du flux OTP par email."""
import pytest


REGISTER_DATA = {
    "email": "otp@example.com",
    "display_name": "OTP User",
    "password": "MotDePasse123!",
}


@pytest.mark.asyncio
async def test_request_otp_success(client):
    await client.post("/api/v1/auth/register", json=REGISTER_DATA)
    response = await client.post(
        "/api/v1/auth/otp/request",
        json={"email": "otp@example.com", "purpose": "login"},
    )
    assert response.status_code == 200
    assert response.json()["success"] is True


@pytest.mark.asyncio
async def test_request_otp_unknown_email_returns_success(client):
    """Anti-énumération : même réponse pour un email inconnu."""
    response = await client.post(
        "/api/v1/auth/otp/request",
        json={"email": "inconnu@example.com", "purpose": "login"},
    )
    assert response.status_code == 200
    assert response.json()["success"] is True


@pytest.mark.asyncio
async def test_verify_otp_wrong_code(client):
    await client.post("/api/v1/auth/register", json=REGISTER_DATA)
    await client.post(
        "/api/v1/auth/otp/request",
        json={"email": "otp@example.com", "purpose": "login"},
    )
    response = await client.post(
        "/api/v1/auth/otp/verify",
        json={"email": "otp@example.com", "code": "000000", "purpose": "login"},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_verify_otp_no_code_requested(client):
    await client.post("/api/v1/auth/register", json=REGISTER_DATA)
    response = await client.post(
        "/api/v1/auth/otp/verify",
        json={"email": "otp@example.com", "code": "123456", "purpose": "login"},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_request_otp_rate_limit(client):
    """Après 5 demandes, la 6e est refusée."""
    await client.post("/api/v1/auth/register", json=REGISTER_DATA)
    for _ in range(5):
        await client.post(
            "/api/v1/auth/otp/request",
            json={"email": "otp@example.com", "purpose": "login"},
        )
    response = await client.post(
        "/api/v1/auth/otp/request",
        json={"email": "otp@example.com", "purpose": "login"},
    )
    assert response.status_code == 429


@pytest.mark.asyncio
async def test_verify_otp_success(client):
    """Test complet : demande + vérification avec code connu (patch)."""
    import auth_backend.services.otp_service as otp_service

    known_code = "123456"

    def fake_generate(length: int = 6) -> str:
        return known_code

    original_generate = otp_service.generate_otp
    otp_service.generate_otp = fake_generate

    try:
        await client.post("/api/v1/auth/register", json=REGISTER_DATA)
        await client.post(
            "/api/v1/auth/otp/request",
            json={"email": "otp@example.com", "purpose": "login"},
        )
        response = await client.post(
            "/api/v1/auth/otp/verify",
            json={"email": "otp@example.com", "code": known_code, "purpose": "login"},
        )
        assert response.status_code == 200
        assert response.json()["success"] is True

        # Le code est maintenant utilisé : un second essai échoue
        response2 = await client.post(
            "/api/v1/auth/otp/verify",
            json={"email": "otp@example.com", "code": known_code, "purpose": "login"},
        )
        assert response2.status_code == 400
    finally:
        otp_service.generate_otp = original_generate
