"""Stockage chiffré des documents de vérification.

Les fichiers sont chiffrés avec Fernet (AES-128 en CBC + HMAC-SHA256)
avant d'être écrits sur disque. La clé de chiffrement est dans
`config.verification_encryption_key`.
"""
from __future__ import annotations

import uuid
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from ..config import AuthConfig
from ..exceptions import StorageError


# Types MIME autorisés pour les documents
ALLOWED_MIME_TYPES = {
    "image/jpeg": ".jpg",
    "image/jpg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
}

MAX_FILE_SIZE_BYTES_DEFAULT = 5 * 1024 * 1024  # 5 Mo


class StorageService:
    """Gère le chiffrement et le stockage local des documents."""

    def __init__(self, config: AuthConfig) -> None:
        self.config = config
        self.base_path = Path(config.verification_storage_path)
        self.base_path.mkdir(parents=True, exist_ok=True)

        if not config.verification_encryption_key:
            raise StorageError(
                "AUTH_VERIFICATION_ENCRYPTION_KEY n'est pas configurée. "
                "Générez-en une avec : "
                "python -c \"from cryptography.fernet import Fernet; "
                "print(Fernet.generate_key().decode())\""
            )

        try:
            self.fernet = Fernet(config.verification_encryption_key.encode())
        except Exception as exc:
            raise StorageError(
                f"Clé de chiffrement invalide : {exc}. "
                "Elle doit être une clé Fernet (44 caractères base64)."
            ) from exc

    # ============================================================
    # Écriture
    # ============================================================
    def save_file(
        self,
        content: bytes,
        original_filename: str | None = None,
        content_type: str | None = None,
        *,
        prefix: str = "doc",
    ) -> str:
        """Chiffre et écrit un fichier sur disque.

        Args:
            content: Le contenu binaire du fichier.
            original_filename: Nom d'origine (facultatif).
            content_type: Type MIME (pour validation).
            prefix: Préfixe du nom de fichier final (ex: "selfie", "doc_front").

        Returns:
            Le chemin relatif du fichier stocké (à conserver en DB).

        Raises:
            VerificationFileTooLargeError, VerificationInvalidFileTypeError, StorageError
        """
        # Validation de la taille
        max_bytes = self.config.verification_upload_max_mb * 1024 * 1024
        if len(content) > max_bytes:
            from ..exceptions import VerificationFileTooLargeError
            raise VerificationFileTooLargeError(self.config.verification_upload_max_mb)

        # Validation du type
        if content_type and content_type not in ALLOWED_MIME_TYPES:
            from ..exceptions import VerificationInvalidFileTypeError
            raise VerificationInvalidFileTypeError()

        # Nom de fichier unique
        ext = ALLOWED_MIME_TYPES.get(content_type or "", ".bin")
        filename = f"{prefix}_{uuid.uuid4().hex}{ext}.enc"
        full_path = self.base_path / filename

        # Chiffrer
        try:
            encrypted = self.fernet.encrypt(content)
        except Exception as exc:
            raise StorageError(f"Échec du chiffrement : {exc}") from exc

        # Écrire
        try:
            full_path.write_bytes(encrypted)
        except OSError as exc:
            raise StorageError(f"Échec de l'écriture sur disque : {exc}") from exc

        # Retourner un chemin relatif (pour la DB)
        return str(full_path.relative_to(self.base_path.parent))

    # ============================================================
    # Lecture
    # ============================================================
    def read_file(self, relative_path: str) -> bytes:
        """Lit et déchiffre un fichier.

        Args:
            relative_path: Le chemin relatif retourné par `save_file`.

        Returns:
            Le contenu binaire déchiffré.

        Raises:
            StorageError si le fichier est introuvable ou corrompu.
        """
        full_path = self.base_path.parent / relative_path
        if not full_path.exists():
            raise StorageError(f"Fichier introuvable : {relative_path}")

        try:
            encrypted = full_path.read_bytes()
            return self.fernet.decrypt(encrypted)
        except InvalidToken as exc:
            raise StorageError(
                "Fichier corrompu ou clé de chiffrement invalide."
            ) from exc
        except OSError as exc:
            raise StorageError(f"Échec de la lecture : {exc}") from exc

    # ============================================================
    # Suppression
    # ============================================================
    def delete_file(self, relative_path: str) -> None:
        """Supprime un fichier chiffré du disque (idempotent)."""
        full_path = self.base_path.parent / relative_path
        try:
            full_path.unlink(missing_ok=True)
        except OSError as exc:
            raise StorageError(f"Échec de la suppression : {exc}") from exc

    def delete_many(self, relative_paths: list[str]) -> None:
        """Supprime plusieurs fichiers (best effort)."""
        for path in relative_paths:
            if path:
                try:
                    self.delete_file(path)
                except StorageError:
                    pass  # best effort
