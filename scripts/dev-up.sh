#!/usr/bin/env bash
set -e

echo "🐳 Démarrage du conteneur PostgreSQL..."
docker start auth-postgres 2>/dev/null || \
  docker run --name auth-postgres \
    -e POSTGRES_USER=auth_user \
    -e POSTGRES_PASSWORD=auth_password_dev \
    -e POSTGRES_DB=auth_db \
    -p 5435:5432 \
    -d postgres:16

echo "⏳ Attente de PostgreSQL..."
sleep 2

echo "✅ Prêt. Lancez :"
echo "   source .venv/bin/activate"
echo "   pytest tests/ -v"
