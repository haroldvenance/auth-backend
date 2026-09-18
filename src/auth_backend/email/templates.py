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



def verification_approved_email(
    display_name: str,
    app_name: str,
) -> tuple[str, str, str]:
    """Email de notification : demande de vérification approuvée."""
    subject = f"Votre compte {app_name} est vérifié"

    body_text = (
        f"Bonjour {display_name},\n\n"
        f"Bonne nouvelle ! Votre demande de vérification d'identité a été approuvée.\n"
        f"Vous avez désormais accès à toutes les fonctionnalités de {app_name}.\n\n"
        f"À bientôt,\n"
        f"L'équipe {app_name}\n"
    )

    body_html = f"""\
<html>
  <body style="font-family: Arial, sans-serif; max-width: 500px; margin: auto;">
    <h2 style="color: #2e7d32;">✅ Compte vérifié</h2>
    <p>Bonjour <strong>{display_name}</strong>,</p>
    <p>Bonne nouvelle ! Votre demande de vérification d'identité a été
       <strong>approuvée</strong>.</p>
    <p>Vous avez désormais accès à toutes les fonctionnalités de
       <strong>{app_name}</strong>.</p>
    <p style="color: #888; font-size: 12px; margin-top: 32px;">
      À bientôt,<br>L'équipe {app_name}
    </p>
  </body>
</html>"""

    return subject, body_text, body_html


def verification_rejected_email(
    display_name: str,
    reason: str,
    attempts_remaining: int,
    app_name: str,
) -> tuple[str, str, str]:
    """Email de notification : demande de vérification rejetée."""
    subject = f"Votre demande de vérification {app_name}"

    if attempts_remaining > 0:
        footer_text = (
            f"Vous pouvez resoumettre une demande avec un document "
            f"conforme. Il vous reste {attempts_remaining} tentative(s).\n"
        )
        footer_html = (
            f"<p>Vous pouvez <strong>resoumettre une demande</strong> avec un "
            f"document conforme. Il vous reste "
            f"<strong>{attempts_remaining} tentative(s)</strong>.</p>"
        )
    else:
        footer_text = (
            "Vous avez atteint le nombre maximum de tentatives. "
            "Contactez le support pour plus d'informations.\n"
        )
        footer_html = (
            "<p style='color: #c62828;'>Vous avez atteint le nombre maximum de "
            "tentatives. Contactez le support pour plus d'informations.</p>"
        )

    body_text = (
        f"Bonjour {display_name},\n\n"
        f"Votre demande de vérification d'identité n'a pas pu être approuvée.\n\n"
        f"Motif : {reason}\n\n"
        f"{footer_text}\n"
        f"Cordialement,\n"
        f"L'équipe {app_name}\n"
    )

    body_html = f"""\
<html>
  <body style="font-family: Arial, sans-serif; max-width: 500px; margin: auto;">
    <h2 style="color: #c62828;"> Demande rejetée</h2>
    <p>Bonjour <strong>{display_name}</strong>,</p>
    <p>Votre demande de vérification d'identité n'a pas pu être approuvée.</p>
    <div style="background: #fff3e0; padding: 12px; border-left: 4px solid #ef6c00;
                border-radius: 4px; margin: 16px 0;">
      <strong>Motif :</strong> {reason}
    </div>
    {footer_html}
    <p style="color: #888; font-size: 12px; margin-top: 32px;">
      Cordialement,<br>L'équipe {app_name}
    </p>
  </body>
</html>"""

    return subject, body_text, body_html