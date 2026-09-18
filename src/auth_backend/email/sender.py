"""Service d'envoi d'emails (SMTP asynchrone)."""
from __future__ import annotations

import logging
from email.message import EmailMessage

import aiosmtplib

from ..config import AuthConfig

logger = logging.getLogger(__name__)


class EmailSender:
    """Envoie des emails via SMTP ou les affiche dans la console.

    Si `console_fallback` est True, les emails ne sont pas envoyés mais
    affichés dans la console — utile en dev/test.
    """

    def __init__(self, config: AuthConfig) -> None:
        self.config = config

    async def send(
        self,
        to: str,
        subject: str,
        body_text: str,
        body_html: str | None = None,
    ) -> None:
        """Envoie un email (ou l'affiche en mode console)."""
        if self.config.email_console_fallback:
            self._print_to_console(to, subject, body_text)
            return

        if not self.config.smtp_user or not self.config.smtp_password:
            logger.warning(
                "SMTP non configuré : email non envoyé. "
                "Définissez AUTH_SMTP_USER et AUTH_SMTP_PASSWORD."
            )
            self._print_to_console(to, subject, body_text)
            return

        message = EmailMessage()
        message["From"] = f"{self.config.email_from_name} <{self.config.email_from}>"
        message["To"] = to
        message["Subject"] = subject
        message.set_content(body_text)
        if body_html:
            message.add_alternative(body_html, subtype="html")

        try:
            await aiosmtplib.send(
                message,
                hostname=self.config.smtp_host,
                port=self.config.smtp_port,
                username=self.config.smtp_user,
                password=self.config.smtp_password,
                start_tls=self.config.smtp_use_tls,
                timeout=10,
            )
            logger.info("Email envoyé à %s : %s", to, subject)
        except Exception as exc:
            logger.error("Échec envoi email à %s : %s", to, exc)
            raise

    @staticmethod
    def _print_to_console(to: str, subject: str, body: str) -> None:
        print("\n" + "=" * 60)
        print(f"📧 EMAIL (mode console)")
        print(f"À      : {to}")
        print(f"Sujet  : {subject}")
        print("-" * 60)
        print(body)
        print("=" * 60 + "\n")
