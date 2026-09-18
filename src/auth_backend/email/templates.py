"""Templates d'emails pour les OTP."""


def otp_email(code: str, expire_minutes: int, app_name: str) -> tuple[str, str, str]:
    """Retourne (subject, body_text, body_html) pour un email OTP."""
    subject = f"Votre code de vérification {app_name}"

    body_text = (
        f"Votre code de vérification est : {code}\n\n"
        f"Ce code est valable {expire_minutes} minutes.\n"
        f"Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.\n"
    )

    body_html = f"""\
<html>
  <body style="font-family: Arial, sans-serif; max-width: 500px; margin: auto;">
    <h2>Code de vérification</h2>
    <p>Voici votre code :</p>
    <p style="font-size: 32px; font-weight: bold; letter-spacing: 4px;
              background: #f4f4f4; padding: 16px; text-align: center;
              border-radius: 8px;">{code}</p>
    <p>Ce code est valable <strong>{expire_minutes} minutes</strong>.</p>
    <p style="color: #888; font-size: 12px;">
      Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.
    </p>
  </body>
</html>"""

    return subject, body_text, body_html
