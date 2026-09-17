"""Modèles SQLAlchemy du module d'authentification."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base


def utcnow() -> datetime:
    """Retourne la date/heure UTC actuelle (timezone-aware)."""
    return datetime.now(timezone.utc)


# ============================================================
# Utilisateur
# ============================================================
class User(Base):
    __tablename__ = "auth_users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )

    # Identifiants
    email: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True, index=True)
    phone: Mapped[str | None] = mapped_column(String(20), unique=True, nullable=True, index=True)
    display_name: Mapped[str] = mapped_column(String(100), nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Statuts
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    verification_status: Mapped[str] = mapped_column(
        String(20), default="unverified", nullable=False, index=True,
    )  # unverified | pending | verified | rejected
    verification_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # TOTP
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    totp_recovery_codes_hash: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Métadonnées
    device_fingerprint_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True,
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False,
    )
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relations
    passkey_credentials: Mapped[list["PasskeyCredential"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="PasskeyCredential.user_id",
    )
    verification_requests: Mapped[list["VerificationRequest"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="VerificationRequest.user_id",
    )
    otp_codes: Mapped[list["OTPCode"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="OTPCode.user_id",
    )
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="RefreshToken.user_id",
    )

    def __repr__(self) -> str:
        return f"<User {self.id} email={self.email} verified={self.is_verified}>"


# ============================================================
# Credentials Passkey (WebAuthn)
# ============================================================
class PasskeyCredential(Base):
    __tablename__ = "auth_passkey_credentials"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("auth_users.id", ondelete="CASCADE"), index=True,
    )

    credential_id: Mapped[str] = mapped_column(String(512), unique=True, nullable=False, index=True)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    aaguid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    transports: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Nom lisible donné par l'utilisateur (ex: "MacBook Pro", "iPhone")
    device_name: Mapped[str | None] = mapped_column(String(100), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False,
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship(
        back_populates="passkey_credentials",
        foreign_keys=[user_id],
    )

    def __repr__(self) -> str:
        return f"<PasskeyCredential {self.id} user={self.user_id}>"


# ============================================================
# Codes OTP
# ============================================================
class OTPCode(Base):
    __tablename__ = "auth_otp_codes"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("auth_users.id", ondelete="CASCADE"), index=True,
    )

    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    code_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    purpose: Mapped[str] = mapped_column(String(50), default="login", nullable=False)
    # login | verify_email | reset_password

    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False,
    )

    user: Mapped["User"] = relationship(
        back_populates="otp_codes",
        foreign_keys=[user_id],
    )

    __table_args__ = (
        Index("ix_otp_email_purpose", "email", "purpose"),
    )


# ============================================================
# Refresh tokens
# ============================================================
class RefreshToken(Base):
    __tablename__ = "auth_refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("auth_users.id", ondelete="CASCADE"), index=True,
    )

    token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Métadonnées de sécurité
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship(
        back_populates="refresh_tokens",
        foreign_keys=[user_id],
    )


# ============================================================
# Demandes de vérification d'identité
# ============================================================
class VerificationRequest(Base):
    __tablename__ = "auth_verification_requests"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("auth_users.id", ondelete="CASCADE"), index=True,
    )

    # Informations saisies
    full_name: Mapped[str] = mapped_column(String(150), nullable=False)
    date_of_birth: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    document_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # cni | passport | student_card | school_card | livret | driver_license | other
    document_number_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Fichiers (chemins chiffrés sur disque)
    selfie_path: Mapped[str] = mapped_column(Text, nullable=False)
    document_front_path: Mapped[str] = mapped_column(Text, nullable=False)
    document_back_path: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Statut
    status: Mapped[str] = mapped_column(
        String(20), default="pending", nullable=False, index=True,
    )  # pending | approved | rejected
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    admin_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Revue
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("auth_users.id", ondelete="SET NULL"), nullable=True,
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False,
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship(
        back_populates="verification_requests",
        foreign_keys=[user_id],
    )

    __table_args__ = (
        # Empêche qu'un même document (hash) soit approuvé deux fois
        Index(
            "ix_verification_document_hash_approved",
            "document_number_hash",
            unique=True,
            postgresql_where=(status == "approved"),
        ),
    )