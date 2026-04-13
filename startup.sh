#!/usr/bin/env bash
# =============================================================================
# CT ComplySphere — Startup Script
# Validates required environment variables, initialises the database schema,
# then launches gunicorn.
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
    exit 1
fi

echo "  DATABASE_URL  : set"
echo "  SESSION_SECRET: set"

# ── 2. Initialise database schema (with retries) ──────────────────────────────
echo ""
echo "[2/3] Initialising database schema..."

DB_INIT_OK=0
for attempt in 1 2 3 4 5; do
    echo "  Attempt $attempt/5..."
    if python3 - <<'PYEOF'
import os, sys, logging
logging.basicConfig(level=logging.INFO)
try:
    from app import app, db
    import models  # noqa: F401
    with app.app_context():
        db.create_all()
    print("  Database schema initialised successfully.")
    sys.exit(0)
except Exception as exc:
    print(f"  DB init failed: {exc}", file=sys.stderr)
    sys.exit(1)
PYEOF
    then
        DB_INIT_OK=1
        break
    else
        echo "  Waiting 10s before retry..."
        sleep 10
    fi
done

if [ "$DB_INIT_OK" -ne 1 ]; then
    echo ""
    echo "  WARNING: Could not initialise database schema after 5 attempts."
    echo "  Starting gunicorn anyway — database errors will appear at request time."
fi

# ── 3. Start gunicorn ─────────────────────────────────────────────────────────
echo ""
echo "[3/3] Starting gunicorn..."
exec gunicorn \
    --bind 0.0.0.0:5000 \
    --workers 2 \
    --timeout 120 \
    --reuse-port \
    main:app
