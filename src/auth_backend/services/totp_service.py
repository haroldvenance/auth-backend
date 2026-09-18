"""Logique métier du TOTP (Time-based One-Time Password).

Le secret TOTP est stocké en clair dans la colonne `User.totp_secret` pour
le MVP. En production, il faudrait le chiffrer au repos (voir
`config.verification_encryption_key` pour un pattern Fernet).
"""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from uuid import UUID

import pyotp
import qrcode
from io import BytesIO
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import AuthConfig
from ..exceptions import (
    RecoveryCodeInvalidError,
    RecoveryCodesExhaustedError,
    TOTPAlreadyEnabledError,
    TOTPInvalidCodeError,
    TOTPNotEnabledError,
    TOTPSetupNotStartedError,
)
from ..models import User
from ..security import hash_otp


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ============================================================
# Setup
# ============================================================
async def start_setup(
    db: AsyncSession,
    user: User,
    config: AuthConfig,
) -> dict:
    """Génère un nouveau secret TOTP et retourne le QR code.

    - Si le TOTP est déjà activé → TOTPAlreadyEnabledError.
    - Si un secret existe déjà (setup en cours) → on réutilise le même
      pour ne pas invalider le QR code que l'utilisateur aurait déjà scanné.
    - Sinon → on génère un nouveau secret.
    """
    if user.totp_enabled:
        raise TOTPAlreadyEnabledError()

    secret = user.totp_secret
    if not secret:
        secret = pyotp.random_base32()
        user.totp_secret = secret
        await db.commit()
        await db.refresh(user)

    # URL otpauth://
    totp = pyotp.TOTP(secret)
    otpauth_url = totp.provisioning_uri(
        name=user.email or user.display_name,
        issuer_name=config.totp_issuer,
    )

    # QR code en data URL
    qr_code_data_url = _make_qr_code_data_url(otpauth_url)

    return {
        "secret": secret,
        "otpauth_url": otpauth_url,
        "qr_code_data_url": qr_code_data_url,
    }


def _make_qr_code_data_url(data: str) -> str:
    """Génère un QR code PNG en data URL base64."""
    import base64

    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buffer = BytesIO()
    img.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


# ============================================================
# Activation
# ============================================================
async def verify_and_enable(
    db: AsyncSession,
    user: User,
    code: str,
    config: AuthConfig,
) -> list[str]:
    """Vérifie un premier code et active le TOTP.

    Retourne la liste des codes de secours générés (à afficher une fois).
    """
    if user.totp_enabled:
        raise TOTPAlreadyEnabledError()

    if not user.totp_secret:
        raise TOTPSetupNotStartedError()

    if not _verify_code(user.totp_secret, code, config.totp_window):
        raise TOTPInvalidCodeError()

    # Générer les codes de secours
    recovery_codes = _generate_recovery_codes(config.totp_recovery_codes_count)

    # Stocker les hashes (avec un flag "used")
    stored = [{"hash": hash_otp(code), "used": False} for code in recovery_codes]
    user.totp_recovery_codes_hash = json.dumps(stored)

    # Activer
    user.totp_enabled = True
    user.updated_at = _utcnow()
    await db.commit()
    await db.refresh(user)

    return recovery_codes


def _generate_recovery_codes(count: int) -> list[str]:
    """Génère des codes de secours au format XXXX-XXXX-XXXX."""
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(6).upper()  # 12 caractères hex
        formatted = f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}"
        codes.append(formatted)
    return codes


def _verify_code(secret: str, code: str, window: int) -> bool:
    """Vérifie un code TOTP avec tolérance ±window périodes."""
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=window)
    except Exception:
        return False


# ============================================================
# Désactivation
# ============================================================
async def disable(
    db: AsyncSession,
    user: User,
    code: str,
    config: AuthConfig,
) -> None:
    """Désactive le TOTP après vérification d'un code valide."""
    if not user.totp_enabled or not user.totp_secret:
        raise TOTPNotEnabledError()

    if not _verify_code(user.totp_secret, code, config.totp_window):
        raise TOTPInvalidCodeError()

    user.totp_enabled = False
    user.totp_secret = None
    user.totp_recovery_codes_hash = None
    user.updated_at = _utcnow()
    await db.commit()


# ============================================================
# Statut
# ============================================================
def get_status(user: User) -> dict:
    """Retourne l'état du TOTP pour un utilisateur."""
    remaining = 0
    if user.totp_recovery_codes_hash:
        try:
            stored = json.loads(user.totp_recovery_codes_hash)
            remaining = sum(1 for item in stored if not item.get("used"))
        except (json.JSONDecodeError, TypeError):
            remaining = 0

    return {
        "enabled": user.totp_enabled,
        "recovery_codes_remaining": remaining,
        "setup_in_progress": (
            bool(user.totp_secret) and not user.totp_enabled
        ),
    }


# ============================================================
# Récupération (recovery code)
# ============================================================
async def use_recovery_code(
    db: AsyncSession,
    email: str,
    recovery_code: str,
) -> User:
    """Utilise un code de secours pour un utilisateur identifié par email.

    Le code est invalidé après usage. Retourne l'utilisateur.
    """
    stmt = select(User).where(User.email == email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not user.totp_enabled or not user.totp_recovery_codes_hash:
        raise RecoveryCodeInvalidError()

    try:
        stored = json.loads(user.totp_recovery_codes_hash)
    except (json.JSONDecodeError, TypeError):
        raise RecoveryCodeInvalidError()

    code_hash = hash_otp(recovery_code)

    for item in stored:
        if item.get("hash") == code_hash and not item.get("used"):
            item["used"] = True
            user.totp_recovery_codes_hash = json.dumps(stored)
            await db.commit()
            await db.refresh(user)
            return user

    # Aucun code trouvé
    if all(item.get("used") for item in stored):
        raise RecoveryCodesExhaustedError()

    raise RecoveryCodeInvalidError()
