#!/usr/bin/env bash
# Render build command: install backend deps + build the React dashboard,
# so uvicorn main:app serves both the API and the static frontend.
set -e

echo "=== Installing Python dependencies ==="
pip install -r requirements.txt

echo "=== Building frontend (React) ==="
# Render free-tier Python images ship nodejs; fall back gracefully if unavailable.
if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
  (cd frontend && npm install --no-audit --no-fund && npm run build)
else
  echo "node/npm not found, skipping frontend build (API-only deploy)."
fi

echo "=== Build complete ==="
