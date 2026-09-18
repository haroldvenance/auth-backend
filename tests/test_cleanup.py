"""Tests du nettoyage des documents de vérification."""
from datetime import datetime, timedelta, timezone

import pytest


async def test_cleanup_dry_run_empty(client, admin_client):
    """Nettoyage sur base vide : rien à supprimer."""
    response = await admin_client.post(
        "/api/v1/auth/admin/cleanup?dry_run=true"
    )
    assert response.status_code == 200
    data = response.json()
    assert data["requests_cleaned"] == 0
    assert data["files_deleted"] == 0
    assert data["dry_run"] is True


async def test_cleanup_requires_admin(client):
    response = await client.post("/api/v1/auth/admin/cleanup")
    assert response.status_code == 401


async def test_cleanup_removes_old_files(client, admin_client, config, db_session):
    """Un document reviewé il y a longtemps est supprimé."""
    import io
    from PIL import Image
    from sqlalchemy import select
    from auth_backend.models import User, VerificationRequest
    from auth_backend.security import hash_document_number
    from auth_backend.services.storage_service import StorageService

    # Créer un user vérifié avec une demande reviewée ancienne
    storage = StorageService(config)

    # Fichiers factices
    img = Image.new("RGB", (50, 50), color="blue")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    img_bytes = buf.getvalue()

    selfie_path = storage.save_file(img_bytes, content_type="image/png", prefix="selfie")
    front_path = storage.save_file(img_bytes, content_type="image/png", prefix="doc_front")

    user = User(
        email="old@example.com",
        display_name="Old User",
        is_active=True,
        is_verified=True,
        verification_status="verified",
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    old_date = datetime.now(timezone.utc) - timedelta(days=30)
    req = VerificationRequest(
        user_id=user.id,
        full_name="Old User",
        document_type="cni",
        document_number_hash=hash_document_number("OLD123"),
        selfie_path=selfie_path,
        document_front_path=front_path,
        status="approved",
        reviewed_at=old_date,
    )
    db_session.add(req)
    await db_session.commit()

    # Lancer le cleanup
    response = await admin_client.post("/api/v1/auth/admin/cleanup")
    assert response.status_code == 200
    data = response.json()
    assert data["requests_cleaned"] >= 1
    assert data["files_deleted"] >= 2

    # Les chemins ont été effacés en DB
    await db_session.refresh(req)
    assert req.selfie_path == ""
    assert req.document_front_path == ""

    # Les fichiers ne sont plus sur le disque
    import os
    full_selfie = storage.base_path.parent / selfie_path
    assert not full_selfie.exists()


async def test_cleanup_keeps_recent_files(client, admin_client, config, db_session):
    """Un document reviewé récemment n'est pas supprimé."""
    import io
    from PIL import Image
    from auth_backend.models import User, VerificationRequest
    from auth_backend.security import hash_document_number
    from auth_backend.services.storage_service import StorageService

    storage = StorageService(config)

    img = Image.new("RGB", (50, 50), color="yellow")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    img_bytes = buf.getvalue()

    selfie_path = storage.save_file(img_bytes, content_type="image/png", prefix="selfie")
    front_path = storage.save_file(img_bytes, content_type="image/png", prefix="doc_front")

    user = User(
        email="recent@example.com",
        display_name="Recent User",
        is_active=True,
        is_verified=True,
        verification_status="verified",
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    # Reviewé il y a 1 jour (dans la période de rétention de 7 jours)
    recent_date = datetime.now(timezone.utc) - timedelta(days=1)
    req = VerificationRequest(
        user_id=user.id,
        full_name="Recent User",
        document_type="cni",
        document_number_hash=hash_document_number("RECENT123"),
        selfie_path=selfie_path,
        document_front_path=front_path,
        status="approved",
        reviewed_at=recent_date,
    )
    db_session.add(req)
    await db_session.commit()

    response = await admin_client.post("/api/v1/auth/admin/cleanup")
    assert response.status_code == 200

    # Le fichier est toujours sur le disque
    full_selfie = storage.base_path.parent / selfie_path
    assert full_selfie.exists()

    # Le chemin en DB est inchangé
    await db_session.refresh(req)
    assert req.selfie_path == selfie_path
