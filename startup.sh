#!/usr/bin/env bash
# =============================================================================
# CT ComplySphere — Startup Script
# Validates required environment variables, initialises the database schema,
# then launches gunicorn. The container will exit non-zero if any required
# variable is missing, making misconfiguration immediately visible.
# =============================================================================
set -euo pipefail

echo "=================================================================="
echo "  CT ComplySphere — Container Startup"
echo "=================================================================="

# ── 1. Validate required environment variables ────────────────────────────────
echo ""
echo "[1/3] Validating required environment variables..."

MISSING_VARS=0

if [ -z "${DATABASE_URL:-}" ]; then
    echo "  ERROR: DATABASE_URL is not set. A PostgreSQL connection string is required."
    MISSING_VARS=1
fi

if [ -z "${SESSION_SECRET:-}" ]; then
    echo "  ERROR: SESSION_SECRET is not set. A random secret string is required."
    MISSING_VARS=1
fi

if [ "$MISSING_VARS" -ne 0 ]; then
    echo ""
    echo "  One or more required environment variables are missing."
    echo "  Copy .env.example to .env, fill in the values, and retry."
    exit 1
fi

echo "  DATABASE_URL  : set"
echo "  SESSION_SECRET: set"

# ── 2. Initialise database schema ─────────────────────────────────────────────
echo ""
echo "[2/3] Initialising database schema..."

python3 - <<'PYEOF'
import os, sys, logging
logging.basicConfig(level=logging.INFO)

try:
    from app import app, db
    import models  # noqa: F401 — ensures all ORM models are registered

    with app.app_context():
        db.create_all()
    print("  Database schema initialised successfully.")
except Exception as exc:
    print(f"  ERROR: Failed to initialise database schema: {exc}", file=sys.stderr)
    sys.exit(1)
PYEOF

# ── 3. Start gunicorn ─────────────────────────────────────────────────────────
echo ""
echo "[3/3] Starting gunicorn..."
exec gunicorn \
    --bind 0.0.0.0:5000 \
    --workers 2 \
    --timeout 120 \
    --reuse-port \
    main:app
