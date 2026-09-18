"""Logique métier des passkeys (WebAuthn / FIDO2)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    options_to_json,
    parse_authentication_credential_json,
    parse_registration_credential_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from ..config import AuthConfig
from ..exceptions import (
    NoPasskeyForUserError,
    PasskeyAlreadyExistsError,
    PasskeyNotFoundError,
    WebAuthnChallengeNotFoundError,
    WebAuthnVerificationError,
)
from ..models import PasskeyCredential, User, WebAuthnChallenge

CHALLENGE_TTL_MINUTES = 5


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ============================================================
# Enregistrement
# ============================================================
async def begin_registration(
    db: AsyncSession,
    user: User,
    config: AuthConfig,
) -> dict:
    """Génère les options d'enregistrement + stocke le challenge en DB."""
    # Credentials existants à exclure
    stmt = select(PasskeyCredential).where(PasskeyCredential.user_id == user.id)
    result = await db.execute(stmt)
    existing = list(result.scalars())

    exclude_credentials = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred.credential_id))
        for cred in existing
    ]

    options = generate_registration_options(
        rp_id=config.webauthn_rp_id,
        rp_name=config.webauthn_rp_name,
        user_id=user.id.bytes,
        user_name=user.email or user.display_name,
        user_display_name=user.display_name,
        exclude_credentials=exclude_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )

    # Stocker le challenge
    challenge_b64 = bytes_to_base64url(options.challenge)
    db_challenge = WebAuthnChallenge(
        user_id=user.id,
        challenge=challenge_b64,
        challenge_type="registration",
        expires_at=_utcnow() + timedelta(minutes=CHALLENGE_TTL_MINUTES),
    )
    db.add(db_challenge)
    await db.commit()

    # Sérialiser en JSON (dict)
    options_dict = json.loads(options_to_json(options))
    return options_dict


async def finish_registration(
    db: AsyncSession,
    user: User,
    credential: dict,
    device_name: str | None,
    config: AuthConfig,
) -> PasskeyCredential:
    """Vérifie la réponse du navigateur et stocke la passkey."""
    # Récupérer le challenge
    stmt = (
        select(WebAuthnChallenge)
        .where(
            WebAuthnChallenge.user_id == user.id,
            WebAuthnChallenge.challenge_type == "registration",
            WebAuthnChallenge.expires_at > _utcnow(),
        )
        .order_by(WebAuthnChallenge.created_at.desc())
        .limit(1)
    )
    result = await db.execute(stmt)
    db_challenge = result.scalar_one_or_none()
    if not db_challenge:
        raise WebAuthnChallengeNotFoundError()

    # Nettoyer le challenge (usage unique)
    await db.delete(db_challenge)
    await db.commit()

    # Vérifier la réponse
    try:
        parsed = parse_registration_credential_json(json.dumps(credential))
        verification = verify_registration_response(
            credential=parsed,
            expected_challenge=base64url_to_bytes(db_challenge.challenge),
            expected_origin=config.webauthn_origin,
            expected_rp_id=config.webauthn_rp_id,
            require_user_verification=False,
        )
    except Exception as exc:
        raise WebAuthnVerificationError(str(exc)) from exc

    credential_id = bytes_to_base64url(verification.credential_id)

    # Vérifier que cette passkey n'existe pas déjà
    existing_stmt = select(PasskeyCredential).where(
        PasskeyCredential.credential_id == credential_id
    )
    existing_result = await db.execute(existing_stmt)
    if existing_result.scalar_one_or_none():
        raise PasskeyAlreadyExistsError()

    # Stocker la passkey
    passkey = PasskeyCredential(
        user_id=user.id,
        credential_id=credential_id,
        public_key=bytes_to_base64url(verification.credential_public_key),
        sign_count=verification.sign_count,
        aaguid=verification.aaguid,
        device_name=device_name or "Passkey",
    )
    db.add(passkey)
    await db.commit()
    await db.refresh(passkey)
    return passkey


# ============================================================
# Authentification
# ============================================================
async def begin_authentication(
    db: AsyncSession,
    config: AuthConfig,
    email: str | None = None,
) -> dict:
    """Génère les options d'authentification."""
    allow_credentials = None
    user_id = None
    email_for_challenge = None

    if email:
        stmt_user = select(User).where(User.email == email)
        result_user = await db.execute(stmt_user)
        user = result_user.scalar_one_or_none()
        if not user:
            # Ne pas révéler si l'email existe : on continue avec des
            # credentials discoverables (le client ne verra pas la différence).
            pass
        else:
            user_id = user.id
            email_for_challenge = user.email
            stmt_creds = select(PasskeyCredential).where(
                PasskeyCredential.user_id == user.id
            )
            result_creds = await db.execute(stmt_creds)
            creds = list(result_creds.scalars())
            if not creds:
                raise NoPasskeyForUserError()
            allow_credentials = [
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id))
                for c in creds
            ]

    options = generate_authentication_options(
        rp_id=config.webauthn_rp_id,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    challenge_b64 = bytes_to_base64url(options.challenge)
    db_challenge = WebAuthnChallenge(
        user_id=user_id,
        challenge=challenge_b64,
        challenge_type="authentication",
        email=email_for_challenge,
        expires_at=_utcnow() + timedelta(minutes=CHALLENGE_TTL_MINUTES),
    )
    db.add(db_challenge)
    await db.commit()

    return json.loads(options_to_json(options))


async def finish_authentication(
    db: AsyncSession,
    credential: dict,
    config: AuthConfig,
) -> User:
    """Vérifie la réponse d'authentification et retourne l'utilisateur."""
    # Extraire le credential_id de la réponse
    try:
        credential_id = credential["id"]
    except (KeyError, TypeError):
        raise WebAuthnVerificationError("Credential ID manquant.")

    # Chercher la passkey correspondante
    stmt = select(PasskeyCredential).where(
        PasskeyCredential.credential_id == credential_id
    )
    result = await db.execute(stmt)
    passkey = result.scalar_one_or_none()
    if not passkey:
        raise WebAuthnVerificationError("Passkey inconnue.")

    # Chercher le challenge correspondant
    challenge_stmt = (
        select(WebAuthnChallenge)
        .where(
            WebAuthnChallenge.user_id == passkey.user_id,
            WebAuthnChallenge.challenge_type == "authentication",
            WebAuthnChallenge.expires_at > _utcnow(),
        )
        .order_by(WebAuthnChallenge.created_at.desc())
        .limit(1)
    )
    challenge_result = await db.execute(challenge_stmt)
    db_challenge = challenge_result.scalar_one_or_none()
    if not db_challenge:
        raise WebAuthnChallengeNotFoundError()

    await db.delete(db_challenge)
    await db.commit()

    # Vérifier la réponse
    try:
        parsed = parse_authentication_credential_json(json.dumps(credential))
        verification = verify_authentication_response(
            credential=parsed,
            expected_challenge=base64url_to_bytes(db_challenge.challenge),
            expected_origin=config.webauthn_origin,
            expected_rp_id=config.webauthn_rp_id,
            credential_public_key=base64url_to_bytes(passkey.public_key),
            credential_current_sign_count=passkey.sign_count,
            require_user_verification=False,
        )
    except Exception as exc:
        raise WebAuthnVerificationError(str(exc)) from exc

    # Mettre à jour sign_count et last_used_at
    passkey.sign_count = verification.new_sign_count
    passkey.last_used_at = _utcnow()
    await db.commit()

    # Récupérer l'utilisateur
    user = await db.get(User, passkey.user_id)
    if not user or not user.is_active:
        raise WebAuthnVerificationError("Utilisateur inactif.")
    return user


# ============================================================
# Gestion
# ============================================================
async def list_passkeys(db: AsyncSession, user: User) -> list[PasskeyCredential]:
    stmt = (
        select(PasskeyCredential)
        .where(PasskeyCredential.user_id == user.id)
        .order_by(PasskeyCredential.created_at.desc())
    )
    result = await db.execute(stmt)
    return list(result.scalars())


async def delete_passkey(
    db: AsyncSession,
    user: User,
    passkey_id: UUID,
) -> None:
    stmt = select(PasskeyCredential).where(
        PasskeyCredential.id == passkey_id,
        PasskeyCredential.user_id == user.id,
    )
    result = await db.execute(stmt)
    passkey = result.scalar_one_or_none()
    if not passkey:
        raise PasskeyNotFoundError()
    await db.delete(passkey)
    await db.commit()


async def rename_passkey(
    db: AsyncSession,
    user: User,
    passkey_id: UUID,
    new_name: str,
) -> PasskeyCredential:
    stmt = select(PasskeyCredential).where(
        PasskeyCredential.id == passkey_id,
        PasskeyCredential.user_id == user.id,
    )
    result = await db.execute(stmt)
    passkey = result.scalar_one_or_none()
    if not passkey:
        raise PasskeyNotFoundError()
    passkey.device_name = new_name
    await db.commit()
    await db.refresh(passkey)
    return passkey
