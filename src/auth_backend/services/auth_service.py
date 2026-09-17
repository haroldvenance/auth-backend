"""Logique métier d'authentification."""
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import AuthConfig
from ..exceptions import (
    EmailAlreadyExistsError,
    InvalidCredentialsError,
    InvalidTokenError,
    MissingIdentifierError,
    PhoneAlreadyExistsError,
)
from ..models import RefreshToken, User
from ..schemas import RegisterRequest, TokenResponse
from ..security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    hash_token,
    validate_password_strength,
    verify_password,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def register_user(
    db: AsyncSession,
    data: RegisterRequest,
    config: AuthConfig,
) -> User:
    """Crée un nouvel utilisateur (non vérifié)."""
    validate_password_strength(data.password)

    if not data.email and not data.phone:
        raise MissingIdentifierError()

    if data.email:
        existing = await db.execute(select(User).where(User.email == data.email))
        if existing.scalar_one_or_none():
            raise EmailAlreadyExistsError()

    if data.phone:
        existing = await db.execute(select(User).where(User.phone == data.phone))
        if existing.scalar_one_or_none():
            raise PhoneAlreadyExistsError()

    user = User(
        email=data.email,
        phone=data.phone,
        display_name=data.display_name,
        password_hash=hash_password(data.password),
        is_active=True,
        is_verified=False,
        verification_status="unverified",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def authenticate_user(
    db: AsyncSession,
    username: str,
    password: str,
) -> User:
    """Authentifie un utilisateur par email/phone + mot de passe."""
    stmt = select(User).where((User.email == username) | (User.phone == username))
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not user.password_hash:
        raise InvalidCredentialsError()

    if not verify_password(password, user.password_hash):
        raise InvalidCredentialsError()

    if not user.is_active:
        raise InvalidCredentialsError()

    user.last_login_at = _utcnow()
    await db.commit()
    await db.refresh(user)
    return user


async def create_tokens_for_user(
    db: AsyncSession,
    user: User,
    config: AuthConfig,
    *,
    user_agent: str | None = None,
    ip_address: str | None = None,
) -> TokenResponse:
    """Crée access + refresh tokens et stocke le refresh en DB."""
    access_token = create_access_token(str(user.id), config)
    refresh_token, expires_at = create_refresh_token(str(user.id), config)

    db_token = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(refresh_token),
        expires_at=expires_at,
        user_agent=user_agent,
        ip_address=ip_address,
    )
    db.add(db_token)
    await db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=config.access_token_expire_minutes * 60,
    )


async def refresh_access_token(
    db: AsyncSession,
    refresh_token: str,
    config: AuthConfig,
) -> tuple[str, int]:
    """Valide un refresh token et émet un nouvel access token."""
    payload = decode_token(refresh_token, config, expected_type="refresh")
    user_id_str = payload.get("sub")
    if not user_id_str:
        raise InvalidTokenError("Refresh token sans sujet")

    token_hash = hash_token(refresh_token)
    stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    result = await db.execute(stmt)
    db_token = result.scalar_one_or_none()

    if not db_token or db_token.revoked:
        raise InvalidTokenError("Refresh token révoqué ou inconnu")

    if db_token.expires_at < _utcnow():
        raise InvalidTokenError("Refresh token expiré")

    user = await db.get(User, UUID(user_id_str))
    if not user or not user.is_active:
        raise InvalidTokenError("Utilisateur introuvable ou inactif")

    new_access = create_access_token(str(user.id), config)
    return new_access, config.access_token_expire_minutes * 60


async def revoke_refresh_token(
    db: AsyncSession,
    refresh_token: str,
) -> None:
    """Révoque un refresh token (idempotent)."""
    token_hash = hash_token(refresh_token)
    stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    result = await db.execute(stmt)
    db_token = result.scalar_one_or_none()

    if db_token and not db_token.revoked:
        db_token.revoked = True
        db_token.revoked_at = _utcnow()
        await db.commit()
