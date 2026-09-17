"""Primitives de sécurité : hachage, JWT, génération de tokens."""
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from pwdlib import PasswordHash

from .config import AuthConfig
from .exceptions import InvalidTokenError, WeakPasswordError

# Hachage Argon2id
password_hasher = PasswordHash.recommended()


# ============================================================
# Mots de passe
# ============================================================
def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return password_hasher.verify(plain, hashed)
    except Exception:
        return False


def validate_password_strength(password: str, min_length: int = 8) -> None:
    """Valide : min_length, 1 maj, 1 min, 1 chiffre."""
    if len(password) < min_length:
        raise WeakPasswordError(f"minimum {min_length} caractères")
    if not any(c.isupper() for c in password):
        raise WeakPasswordError("au moins une majuscule requise")
    if not any(c.islower() for c in password):
        raise WeakPasswordError("au moins une minuscule requise")
    if not any(c.isdigit() for c in password):
        raise WeakPasswordError("au moins un chiffre requis")


# ============================================================
# JWT
# ============================================================
def create_access_token(user_id: str, config: AuthConfig) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=config.access_token_expire_minutes)
    payload = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "type": "access",
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, config.secret_key, algorithm=config.algorithm)


def create_refresh_token(user_id: str, config: AuthConfig) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=config.refresh_token_expire_days)
    payload = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "type": "refresh",
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(payload, config.secret_key, algorithm=config.algorithm)
    return token, expire


def decode_token(token: str, config: AuthConfig, expected_type: str | None = None) -> dict:
    try:
        payload = jwt.decode(token, config.secret_key, algorithms=[config.algorithm])
    except JWTError as e:
        raise InvalidTokenError(f"Token invalide : {e}") from e

    if expected_type and payload.get("type") != expected_type:
        raise InvalidTokenError(f"Type de token invalide (attendu : {expected_type})")

    return payload


# ============================================================
# Hachage déterministe (lookup en DB)
# ============================================================
def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_otp(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def hash_document_number(document_number: str) -> str:
    normalized = document_number.strip().upper().replace(" ", "").replace("-", "")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


# ============================================================
# OTP
# ============================================================
def generate_otp(length: int = 6) -> str:
    max_value = 10 ** length
    return str(secrets.randbelow(max_value)).zfill(length)
