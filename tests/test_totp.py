"""Tests du flux TOTP."""
import pyotp
import pytest


REGISTER_DATA = {
    "email": "totp@example.com",
    "display_name": "TOTP User",
    "password": "MotDePasse123!",
}


async def _register_and_login(client) -> str:
    """Helper : inscrit et connecte un utilisateur, retourne le token."""
    await client.post("/api/v1/auth/register", json=REGISTER_DATA)
    login = await client.post(
        "/api/v1/auth/token",
        data={"username": "totp@example.com", "password": "MotDePasse123!"},
    )
    return login.json()["access_token"]


@pytest.mark.asyncio
async def test_status_initially_disabled(client):
    token = await _register_and_login(client)
    response = await client.get(
        "/api/v1/auth/totp/status",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["enabled"] is False
    assert data["recovery_codes_remaining"] == 0


@pytest.mark.asyncio
async def test_setup_returns_qr_and_secret(client):
    token = await _register_and_login(client)
    response = await client.post(
        "/api/v1/auth/totp/setup",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "secret" in data
    assert "otpauth_url" in data
    assert data["qr_code_data_url"].startswith("data:image/png;base64,")


@pytest.mark.asyncio
async def test_setup_twice_returns_same_secret(client):
    """Un second appel à /setup ne régénère pas le secret (QR cohérent)."""
    token = await _register_and_login(client)
    headers = {"Authorization": f"Bearer {token}"}

    r1 = await client.post("/api/v1/auth/totp/setup", headers=headers)
    r2 = await client.post("/api/v1/auth/totp/setup", headers=headers)
    assert r1.json()["secret"] == r2.json()["secret"]


@pytest.mark.asyncio
async def test_verify_with_wrong_code_fails(client):
    token = await _register_and_login(client)
    headers = {"Authorization": f"Bearer {token}"}

    await client.post("/api/v1/auth/totp/setup", headers=headers)
    response = await client.post(
        "/api/v1/auth/totp/verify",
        headers=headers,
        json={"code": "000000"},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_verify_and_enable_success(client):
    """Flux complet : setup → verify avec un code généré → enabled."""
    token = await _register_and_login(client)
    headers = {"Authorization": f"Bearer {token}"}

    setup = await client.post("/api/v1/auth/totp/setup", headers=headers)
    secret = setup.json()["secret"]

    # Générer un code valide avec pyotp
    totp = pyotp.TOTP(secret)
    code = totp.now()

    response = await client.post(
        "/api/v1/auth/totp/verify",
        headers=headers,
        json={"code": code},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["recovery_codes"] is not None
    assert len(data["recovery_codes"]) == 8

    # Le statut doit maintenant être enabled
    status_resp = await client.get("/api/v1/auth/totp/status", headers=headers)
    assert status_resp.json()["enabled"] is True
    assert status_resp.json()["recovery_codes_remaining"] == 8


@pytest.mark.asyncio
async def test_disable_requires_valid_code(client):
    token = await _register_and_login(client)
    headers = {"Authorization": f"Bearer {token}"}

    setup = await client.post("/api/v1/auth/totp/setup", headers=headers)
    secret = setup.json()["secret"]
    code = pyotp.TOTP(secret).now()

    # Activer
    await client.post(
        "/api/v1/auth/totp/verify",
        headers=headers,
        json={"code": code},
    )

    # Désactiver avec un mauvais code → échec
    bad = await client.post(
        "/api/v1/auth/totp/disable",
        headers=headers,
        json={"code": "000000"},
    )
    assert bad.status_code == 400

    # Désactiver avec un bon code → 204
    good_code = pyotp.TOTP(secret).now()
    ok = await client.post(
        "/api/v1/auth/totp/disable",
        headers=headers,
        json={"code": good_code},
    )
    assert ok.status_code == 204

    # Statut : disabled
    status_resp = await client.get("/api/v1/auth/totp/status", headers=headers)
    assert status_resp.json()["enabled"] is False


@pytest.mark.asyncio
async def test_recovery_code_flow(client):
    """Flux complet : activer → utiliser un code de secours."""
    token = await _register_and_login(client)
    headers = {"Authorization": f"Bearer {token}"}

    setup = await client.post("/api/v1/auth/totp/setup", headers=headers)
    secret = setup.json()["secret"]
    code = pyotp.TOTP(secret).now()

    verify = await client.post(
        "/api/v1/auth/totp/verify",
        headers=headers,
        json={"code": code},
    )
    recovery_codes = verify.json()["recovery_codes"]

    # Utiliser le premier code de secours
    response = await client.post(
        "/api/v1/auth/totp/recovery",
        json={
            "email": "totp@example.com",
            "recovery_code": recovery_codes[0],
        },
    )
    assert response.status_code == 200

    # Réutiliser le même code → échec
    response2 = await client.post(
        "/api/v1/auth/totp/recovery",
        json={
            "email": "totp@example.com",
            "recovery_code": recovery_codes[0],
        },
    )
    assert response2.status_code == 400

    # Vérifier que le compteur est passé à 7
    status_resp = await client.get("/api/v1/auth/totp/status", headers=headers)
    assert status_resp.json()["recovery_codes_remaining"] == 7


@pytest.mark.asyncio
async def test_recovery_code_invalid(client):
    await _register_and_login(client)
    response = await client.post(
        "/api/v1/auth/totp/recovery",
        json={"email": "totp@example.com", "recovery_code": "AAAA-BBBB-CCCC"},
    )
    assert response.status_code == 400
