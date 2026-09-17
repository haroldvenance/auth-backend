"""Tests du flux d'authentification."""
import pytest


REGISTER_DATA = {
    "email": "test@example.com",
    "display_name": "Test User",
    "password": "MotDePasse123!",
}


@pytest.mark.asyncio
async def test_register_success(client):
    response = await client.post("/api/v1/auth/register", json=REGISTER_DATA)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "test@example.com"
    assert data["display_name"] == "Test User"
    assert data["is_verified"] is False
    assert data["verification_status"] == "unverified"
    assert "password" not in data
    assert "password_hash" not in data


@pytest.mark.asyncio
async def test_register_duplicate_email(client):
    await client.post("/api/v1/auth/register", json=REGISTER_DATA)
    response = await client.post("/api/v1/auth/register", json=REGISTER_DATA)
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_register_weak_password(client):
    data = {**REGISTER_DATA, "password": "weak"}
    response = await client.post("/api/v1/auth/register", json=data)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_login_success(client):
    await client.post("/api/v1/auth/register", json=REGISTER_DATA)
    response = await client.post(
        "/api/v1/auth/token",
        data={"username": "test@example.com", "password": "MotDePasse123!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    await client.post("/api/v1/auth/register", json=REGISTER_DATA)
    response = await client.post(
        "/api/v1/auth/token",
        data={"username": "test@example.com", "password": "WrongPassword123!"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_me_endpoint(client):
    await client.post("/api/v1/auth/register", json=REGISTER_DATA)
    login = await client.post(
        "/api/v1/auth/token",
        data={"username": "test@example.com", "password": "MotDePasse123!"},
    )
    token = login.json()["access_token"]

    response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["email"] == "test@example.com"


@pytest.mark.asyncio
async def test_me_without_token(client):
    response = await client.get("/api/v1/auth/me")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_refresh_token(client):
    await client.post("/api/v1/auth/register", json=REGISTER_DATA)
    login = await client.post(
        "/api/v1/auth/token",
        data={"username": "test@example.com", "password": "MotDePasse123!"},
    )
    refresh_token = login.json()["refresh_token"]

    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert response.status_code == 200
    assert "access_token" in response.json()


@pytest.mark.asyncio
async def test_logout(client):
    await client.post("/api/v1/auth/register", json=REGISTER_DATA)
    login = await client.post(
        "/api/v1/auth/token",
        data={"username": "test@example.com", "password": "MotDePasse123!"},
    )
    refresh_token = login.json()["refresh_token"]

    response = await client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": refresh_token},
    )
    assert response.status_code == 204

    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert response.status_code == 401

