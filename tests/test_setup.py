"""Test d'intégration du setup du module."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from auth_backend import AuthConfig, setup_auth


@pytest.fixture
def config() -> AuthConfig:
    return AuthConfig(
        database_url="postgresql+asyncpg://auth_user:auth_password_dev@localhost:5435/auth_db_test",
        secret_key="test-secret-key-with-at-least-32-characters-long",
        api_prefix="/api/v1/auth",
    )


@pytest.fixture
def app(config: AuthConfig) -> FastAPI:
    app = FastAPI()
    setup_auth(app, config)
    return app


def test_health_endpoint(app: FastAPI):
    client = TestClient(app)
    response = client.get("/api/v1/auth/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["module"] == "auth-backend"
    assert "version" in data


def test_config_stored_in_app_state(app: FastAPI, config: AuthConfig):
    assert app.state.auth_config is config
    assert app.state.auth_config.api_prefix == "/api/v1/auth"


def test_cors_origins_parsing():
    cfg = AuthConfig(cors_origins="http://a.com,http://b.com, http://c.com")
    assert cfg.cors_origins == ["http://a.com", "http://b.com", "http://c.com"]
