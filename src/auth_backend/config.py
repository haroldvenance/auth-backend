"""Configuration centralisée du module d'authentification."""
from functools import lru_cache
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthConfig(BaseSettings):
    """Configuration du module d'authentification.

    Toutes les valeurs peuvent être surchargées via des variables
    d'environnement préfixées par AUTH_ (ex: AUTH_SECRET_KEY).
    """

    model_config = SettingsConfigDict(
        env_prefix="AUTH_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ===== Base de données =====
    database_url: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/auth_db",
        description="URL de connexion à PostgreSQL (asyncpg)",
    )
    db_echo: bool = Field(default=False, description="Log les requêtes SQL")
    db_pool_size: int = Field(default=5, ge=1, le=50)
    db_max_overflow: int = Field(default=10, ge=0, le=100)
    db_use_null_pool: bool = Field(
        default=False,
        description=(
            "Utilise NullPool au lieu du pool par défaut. "
            "Recommandé en tests pour éviter les conflits de boucle asyncio."
        ),
    )

    # ===== JWT =====
    secret_key: str = Field(
        default="changez-moi-en-production-avec-openssl-rand-hex-32",
        min_length=32,
        description="Clé secrète pour signer les JWT",
    )
    algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=30, ge=1, le=1440)
    refresh_token_expire_days: int = Field(default=7, ge=1, le=90)

    # ===== OTP par email =====
    otp_length: int = Field(default=6, ge=4, le=10)
    otp_expire_minutes: int = Field(default=10, ge=1, le=60)
    otp_max_attempts: int = Field(default=5, ge=1, le=10)
    otp_rate_limit_per_hour: int = Field(default=5, ge=1, le=20)

    # ===== SMTP =====
    smtp_host: str = Field(default="smtp-relay.brevo.com")
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_user: str = Field(default="")
    smtp_password: str = Field(default="")
    smtp_use_tls: bool = Field(default=True)
    email_from: str = Field(default="noreply@example.com")
    email_from_name: str = Field(default="Auth Module")

    # ===== TOTP =====
    totp_issuer: str = Field(default="AuthModule", description="Nom affiché dans l'app authenticator")
    totp_window: int = Field(default=1, ge=0, le=5, description="Tolérance en périodes de 30s")
    totp_recovery_codes_count: int = Field(default=8, ge=4, le=16)

    # ===== WebAuthn / Passkeys =====
    webauthn_rp_id: str = Field(default="localhost", description="Domaine (sans https://)")
    webauthn_rp_name: str = Field(default="Auth Module")
    webauthn_origin: str = Field(default="http://localhost:5173", description="Origine complète")

    # ===== Vérification d'identité =====
    verification_max_attempts: int = Field(default=3, ge=1, le=10)
    verification_retention_days: int = Field(default=7, ge=1, le=90)
    verification_upload_max_mb: int = Field(default=5, ge=1, le=20)
    verification_storage_path: str = Field(
        default="./storage/verifications",
        description="Dossier de stockage des documents chiffrés",
    )
    verification_encryption_key: str = Field(
        default="",
        description="Clé Fernet (44 chars base64) pour chiffrer les documents",
    )

    # ===== Divers =====
    debug: bool = Field(default=False)
    api_prefix: str = Field(default="/api/v1/auth")
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        """Accepte une chaîne séparée par des virgules ou une liste."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        if v.startswith("changez-moi") and not cls.model_config.get("debug"):
            import warnings
            warnings.warn(
                "⚠️  AUTH_SECRET_KEY utilise la valeur par défaut. "
                "Générez-en une nouvelle avec: openssl rand -hex 32",
                stacklevel=2,
            )
        return v


@lru_cache
def get_config() -> AuthConfig:
    """Retourne une instance unique (singleton) de la configuration."""
    return AuthConfig()