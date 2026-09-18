"""Tests du flux Passkeys (WebAuthn).

Les tests d'enregistrement et d'authentification complète mockent
les fonctions `verify_registration_response` et
`verify_authentication_response` du package `webauthn`. Cela permet de
tester toute la logique côté serveur (challenge, stockage, tokens) sans
nécessiter un authentificateur matériel.
"""
from unittest.mock import MagicMock

import pytest


REGISTER_DATA = {
    "email": "passkey@example.com",
    "display_name": "Passkey User",
    "password": "MotDePasse123!",
}


async def _register_and_login(client) -> str:
    await client.post("/api/v1/auth/register", json=REGISTER_DATA)
    login = await client.post(
        "/api/v1/auth/token",
        data={"username": "passkey@example.com", "password": "MotDePasse123!"},
    )
    return login.json()["access_token"]


# ============================================================
# Enregistrement
# ============================================================
@pytest.mark.asyncio
async def test_register_begin_requires_auth(client):
    response = await client.post("/api/v1/auth/passkeys/register/begin")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_register_begin_returns_options(client):
    token = await _register_and_login(client)
    response = await client.post(
        "/api/v1/auth/passkeys/register/begin",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "options" in data
    options = data["options"]
    assert "challenge" in options
    assert "rp" in options
    assert "user" in options
    assert options["rp"]["id"] == "test"


@pytest.mark.asyncio
async def test_register_begin_stores_challenge(client, db_session):
    """Vérifie qu'un challenge est bien stocké en DB."""
    from sqlalchemy import select
    from auth_backend.models import WebAuthnChallenge

    token = await _register_and_login(client)
    await client.post(
        "/api/v1/auth/passkeys/register/begin",
        headers={"Authorization": f"Bearer {token}"},
    )

    stmt = select(WebAuthnChallenge).where(
        WebAuthnChallenge.challenge_type == "registration"
    )
    result = await db_session.execute(stmt)
    challenges = list(result.scalars())
    assert len(challenges) == 1


@pytest.mark.asyncio
async def test_register_finish_success(client, monkeypatch):
    """Mock verify_registration_response pour simuler un succès."""
    from auth_backend.services import passkey_service

    # Mock du résultat de vérification
    fake_verification = MagicMock()
    fake_verification.credential_id = b"\x01\x02\x03\x04"
    fake_verification.credential_public_key = b"\xaa\xbb\xcc\xdd"
    fake_verification.sign_count = 0
    fake_verification.aaguid = "00000000-0000-0000-0000-000000000000"

    def fake_verify(*args, **kwargs):
        return fake_verification

    monkeypatch.setattr(
        passkey_service, "verify_registration_response", fake_verify
    )

    token = await _register_and_login(client)
    headers = {"Authorization": f"Bearer {token}"}

    # Begin
    await client.post("/api/v1/auth/passkeys/register/begin", headers=headers)

    # Finish (credential factice)
    response = await client.post(
        "/api/v1/auth/passkeys/register/finish",
        headers=headers,
        json={
            "credential": {
                "id": "AQIDBA",
                "rawId": "AQIDBA",
                "type": "public-key",
                "response": {
                    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
                    "attestationObject": "o2NmbXRkbm9uZQ",
                },
            },
            "device_name": "Ma YubiKey",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["device_name"] == "Ma YubiKey"
    assert "id" in data


@pytest.mark.asyncio
async def test_register_finish_without_begin_fails(client):
    token = await _register_and_login(client)
    response = await client.post(
        "/api/v1/auth/passkeys/register/finish",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "credential": {
                "id": "AQIDBA",
                "rawId": "AQIDBA",
                "type": "public-key",
                "response": {
                    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
                    "attestationObject": "o2NmbXRkbm9uZQ",
                },
            },
        },
    )
    assert response.status_code == 400


# ============================================================
# Liste et gestion
# ============================================================
@pytest.mark.asyncio
async def test_list_passkeys_empty(client):
    token = await _register_and_login(client)
    response = await client.get(
        "/api/v1/auth/passkeys",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_delete_passkey_not_found(client):
    token = await _register_and_login(client)
    response = await client.delete(
        "/api/v1/auth/passkeys/00000000-0000-0000-0000-000000000000",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


# ============================================================
# Authentification
# ============================================================
@pytest.mark.asyncio
async def test_authenticate_begin_no_email_returns_options(client):
    """Authentification discoverable (sans email)."""
    response = await client.post(
        "/api/v1/auth/passkeys/authenticate/begin",
        json={},
    )
    assert response.status_code == 200
    assert "options" in response.json()
    assert "challenge" in response.json()["options"]


@pytest.mark.asyncio
async def test_authenticate_begin_with_email_unknown_user_fails(client):
    """Email inconnu → on retourne des options discoverables malgré tout."""
    response = await client.post(
        "/api/v1/auth/passkeys/authenticate/begin",
        json={"email": "inconnu@example.com"},
    )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_authenticate_begin_with_email_no_passkey_fails(client):
    """Email connu mais pas de passkey → erreur explicite."""
    await _register_and_login(client)
    response = await client.post(
        "/api/v1/auth/passkeys/authenticate/begin",
        json={"email": "passkey@example.com"},
    )
    assert response.status_code == 400
