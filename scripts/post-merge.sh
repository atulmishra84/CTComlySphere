#!/bin/bash
set -e

echo "=== Post-merge: installing Python dependencies ==="
pip install --quiet -r requirements-azure.txt 2>&1 | tail -5 || \
pip install --quiet -r requirements.txt 2>&1 | tail -5 || true

echo "=== Post-merge: initialising database schema ==="
python3 -c "
from app import app, db
with app.app_context():
    import models
    db.create_all()
    print('Database schema OK')
"

echo "=== Post-merge: complete ==="
