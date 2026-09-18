"""Logique métier des codes OTP."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import AuthConfig
from ..email.sender import EmailSender
from ..email.templates import otp_email
from ..exceptions import (
    OTPExpiredError,
    OTPInvalidError,
    OTPMaxAttemptsError,
    OTPRateLimitError,
)
from ..models import OTPCode, User
from ..security import generate_otp, hash_otp


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def request_otp(
    db: AsyncSession,
    config: AuthConfig,
    email: str,
    purpose: str = "login",
) -> None:
    """Génère et envoie un code OTP à l'email donné.

    - Invalide les anciens codes non utilisés pour ce (email, purpose).
    - Applique un rate limiting : max N demandes par heure.
    - Envoie l'email via le service SMTP.
    """
    # Rate limiting
    one_hour_ago = _utcnow() - timedelta(hours=1)
    stmt_count = select(func.count(OTPCode.id)).where(
        OTPCode.email == email,
        OTPCode.purpose == purpose,
        OTPCode.created_at >= one_hour_ago,
    )
    result = await db.execute(stmt_count)
    count = result.scalar_one()
    if count >= config.otp_rate_limit_per_hour:
        raise OTPRateLimitError()

    # Chercher l'utilisateur (facultatif)
    stmt_user = select(User).where(User.email == email)
    result_user = await db.execute(stmt_user)
    user = result_user.scalar_one_or_none()

    # Invalider les anciens codes non utilisés
    stmt_invalidate = select(OTPCode).where(
        OTPCode.email == email,
        OTPCode.purpose == purpose,
        OTPCode.used == False,  # noqa: E712
    )
    result_invalidate = await db.execute(stmt_invalidate)
    for old_code in result_invalidate.scalars():
        old_code.used = True

    # Générer et stocker le nouveau code
    code = generate_otp(config.otp_length)
    otp = OTPCode(
        user_id=user.id if user else None,
        email=email,
        code_hash=hash_otp(code),
        purpose=purpose,
        expires_at=_utcnow() + timedelta(minutes=config.otp_expire_minutes),
    )
    db.add(otp)
    await db.commit()

    # Envoyer l'email
    subject, body_text, body_html = otp_email(
        code=code,
        expire_minutes=config.otp_expire_minutes,
        app_name=config.totp_issuer,
    )
    sender = EmailSender(config)
    await sender.send(
        to=email,
        subject=subject,
        body_text=body_text,
        body_html=body_html,
    )


async def verify_otp(
    db: AsyncSession,
    config: AuthConfig,
    email: str,
    code: str,
    purpose: str = "login",
) -> OTPCode:
    """Vérifie un code OTP et le marque comme utilisé.

    Raises:
        OTPInvalidError, OTPExpiredError, OTPMaxAttemptsError
    """
    stmt = (
        select(OTPCode)
        .where(
            OTPCode.email == email,
            OTPCode.purpose == purpose,
            OTPCode.used == False,  # noqa: E712
        )
        .order_by(OTPCode.created_at.desc())
        .limit(1)
    )
    result = await db.execute(stmt)
    otp = result.scalar_one_or_none()

    if otp is None:
        raise OTPInvalidError()

    if otp.expires_at < _utcnow():
        raise OTPExpiredError()

    if otp.attempts >= config.otp_max_attempts:
        raise OTPMaxAttemptsError()

    if otp.code_hash != hash_otp(code):
        otp.attempts += 1
        await db.commit()
        raise OTPInvalidError()

    otp.used = True
    await db.commit()
    await db.refresh(otp)
    return otp