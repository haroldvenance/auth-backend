"""Test rapide de la configuration SMTP."""
import asyncio
import sys

from auth_backend.config import AuthConfig
from auth_backend.email.sender import EmailSender


async def main():
    config = AuthConfig()
    print(f"Host      : {config.smtp_host}")
    print(f"Port      : {config.smtp_port}")
    print(f"User      : {config.smtp_user}")
    print(f"TLS       : {config.smtp_use_tls}")
    print(f"From      : {config.email_from}")
    print(f"Fallback  : {config.email_console_fallback}")
    print()

    if not config.smtp_user or not config.smtp_password:
        print("❌ SMTP_USER ou SMTP_PASSWORD non configuré dans .env")
        sys.exit(1)

    to = input("Destinataire de test (email) : ").strip()
    if not to:
        print("❌ Aucun destinataire fourni.")
        sys.exit(1)

    sender = EmailSender(config)
    print(f"📤 Envoi d'un email de test à {to}...")
    try:
        await sender.send(
            to=to,
            subject="Test SMTP - Auth Module",
            body_text="Ceci est un test de configuration SMTP.\nSi vous lisez ce message, tout fonctionne !",
        )
        print("✅ Email envoyé avec succès.")
    except Exception as exc:
        print(f"❌ Échec : {exc}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
