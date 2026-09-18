"""Schémas Pydantic pour les requêtes et réponses de l'API."""
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr | None = None
    phone: str | None = None
    display_name: str
    is_active: bool
    is_verified: bool
    verification_status: str
    totp_enabled: bool
    created_at: datetime
    last_login_at: datetime | None = None


class RegisterRequest(BaseModel):
    email: EmailStr | None = None
    phone: str | None = Field(default=None, min_length=6, max_length=20)
    display_name: str = Field(min_length=2, max_length=100)
    password: str = Field(min_length=8, max_length=128)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com",
                "display_name": "Jean Dupont",
                "password": "MotDePasse123!",
            }
        }
    )


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class RefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int



# ============================================================
# OTP
# ============================================================
class OTPRequest(BaseModel):
    email: EmailStr
    purpose: str = Field(
        default="login",
        pattern="^(login|verify_email|reset_password)$",
    )


class OTPVerifyRequest(BaseModel):
    email: EmailStr
    code: str = Field(min_length=4, max_length=10)
    purpose: str = Field(
        default="login",
        pattern="^(login|verify_email|reset_password)$",
    )


class OTPResponse(BaseModel):
    success: bool = True
    message: str
    
    
    
    
    
# ============================================================
# TOTP
# ============================================================
class TOTPSetupResponse(BaseModel):
    """Retourné par /totp/setup — contient le secret et le QR code."""
    secret: str = Field(description="Secret base32 à conserver précieusement")
    otpauth_url: str = Field(description="URL otpauth:// à utiliser pour le QR code")
    qr_code_data_url: str = Field(
        description="QR code encodé en data URL (image/png;base64,...)"
    )


class TOTPVerifyRequest(BaseModel):
    """Vérifie un code TOTP à 6 chiffres."""
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class TOTPVerifyResponse(BaseModel):
    success: bool = True
    message: str
    recovery_codes: list[str] | None = Field(
        default=None,
        description="Codes de secours générés. Affichés une seule fois.",
    )


class TOTPDisableRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class TOTPStatusResponse(BaseModel):
    enabled: bool
    recovery_codes_remaining: int = 0
    setup_in_progress: bool = False


class TOTPRecoveryRequest(BaseModel):
    email: EmailStr
    recovery_code: str = Field(min_length=8, max_length=32)
    
    
    
    
    
    
    
    
    
# ============================================================
# Passkeys / WebAuthn
# ============================================================
class PasskeyResponse(BaseModel):
    """Représentation d'une passkey enregistrée."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    device_name: str | None = None
    created_at: datetime
    last_used_at: datetime | None = None


class RegistrationBeginResponse(BaseModel):
    """Options renvoyées au client pour démarrer l'enregistrement.

    Le contenu exact est un objet PublicKeyCredentialCreationOptions
    sérialisé en JSON (clé `options`).
    """
    options: dict


class RegistrationFinishRequest(BaseModel):
    """Réponse du navigateur après création d'une passkey."""
    credential: dict
    device_name: str | None = Field(default=None, max_length=100)


class AuthenticationBeginRequest(BaseModel):
    """Démarrage de l'authentification.

    Si `email` est fourni, on restreint aux credentials de cet utilisateur.
    Sinon, on utilise des credentials discoverable (passkey sans email).
    """
    email: EmailStr | None = None


class AuthenticationBeginResponse(BaseModel):
    options: dict


class AuthenticationFinishRequest(BaseModel):
    """Réponse du navigateur après authentification."""
    credential: dict


class AuthenticationFinishResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: "UserResponse"


class PasskeyRenameRequest(BaseModel):
    device_name: str = Field(min_length=1, max_length=100)


# Résolution de la référence circulaire
AuthenticationFinishResponse.model_rebuild()









# ============================================================
# Vérification d'identité
# ============================================================
class VerificationRequestResponse(BaseModel):
    """Détails d'une demande de vérification."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    full_name: str
    document_type: str
    status: str
    rejection_reason: str | None = None
    created_at: datetime
    reviewed_at: datetime | None = None


class VerificationLatestInfo(BaseModel):
    id: str
    status: str
    document_type: str
    created_at: str
    reviewed_at: str | None = None
    rejection_reason: str | None = None


class VerificationStatusResponse(BaseModel):
    """Statut de vérification d'un utilisateur."""
    status: str  # unverified | pending | verified | rejected
    is_verified: bool
    attempts: int
    max_attempts: int
    latest_request: VerificationLatestInfo | None = None