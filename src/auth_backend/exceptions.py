"""Exceptions métier du module d'authentification."""
from fastapi import HTTPException, status


class AuthError(HTTPException):
    """Exception de base pour toutes les erreurs d'authentification."""
    pass


class EmailAlreadyExistsError(AuthError):
    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail="Un compte avec cet email existe déjà",
        )


class PhoneAlreadyExistsError(AuthError):
    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail="Un compte avec ce numéro de téléphone existe déjà",
        )


class InvalidCredentialsError(AuthError):
    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou mot de passe incorrect",
            headers={"WWW-Authenticate": "Bearer"},
        )


class InvalidTokenError(AuthError):
    def __init__(self, detail: str = "Token invalide ou expiré") -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


class InactiveUserError(AuthError):
    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Ce compte est désactivé",
        )


class UnverifiedUserError(AuthError):
    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Votre compte doit être vérifié pour accéder à cette fonctionnalité",
        )


class AdminRequiredError(AuthError):
    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Accès administrateur requis",
        )


class WeakPasswordError(AuthError):
    def __init__(self, reason: str) -> None:
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Mot de passe trop faible : {reason}",
        )


class MissingIdentifierError(AuthError):
    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Un email ou un numéro de téléphone est requis",
        )







class OTPExpiredError(AuthError):
    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ce code a expiré. Demandez-en un nouveau.",
        )


class OTPInvalidError(AuthError):
    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Code incorrect.",
        )


class OTPAlreadyUsedError(AuthError):
    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ce code a déjà été utilisé.",
        )


class OTPMaxAttemptsError(AuthError):
    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Trop de tentatives. Demandez un nouveau code.",
        )


class OTPRateLimitError(AuthError):
    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Trop de demandes de code. Réessayez dans une heure.",
        )


class EmailNotConfiguredError(AuthError):
    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Le service d'email n'est pas configuré.",
        )