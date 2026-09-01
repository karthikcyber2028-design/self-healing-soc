"""Render/web entry point for the full Self-Healing SOC project.

Serves the FastAPI backend API plus the built React dashboard (frontend/dist)
from a single Python web service.
"""
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.app.main import app as api_app

app = api_app

FRONTEND_DIST = Path(__file__).resolve().parent / "frontend" / "dist"
INDEX = FRONTEND_DIST / "index.html"


@app.get("/", include_in_schema=False)
def index():
    if INDEX.exists():
        return FileResponse(INDEX)
    return FileResponse(Path(__file__).resolve().parent / "backend" / "static_fallback.html")


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return FileResponse(INDEX) if INDEX.exists() else FileResponse(
        Path(__file__).resolve().parent / "backend" / "static_fallback.html")


# Mount built frontend assets (JS/CSS/images) at /assets
if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")
