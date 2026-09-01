import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from .db import Base, SessionLocal, engine
from .models import User
from .routers import auth, reports, soc
from .security import hash_password

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Self-Healing SOC Agent API",
    version="2.0",
    description=(
        "AI-powered Security Operations Center with automated detection and "
        "simulated self-healing responses. Educational/defensive simulation only."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DEMO_USERS = [
    ("admin", "Admin@12345", "admin"),
    ("analyst", "Analyst@12345", "analyst"),
    ("viewer", "Viewer@12345", "viewer"),
]


@app.on_event("startup")
def seed_users():
    with SessionLocal() as db:
        existing = db.scalars(select(User.username)).all()
        for username, password, role in DEMO_USERS:
            if username not in existing:
                db.add(User(username=username, password_hash=hash_password(password), role=role))
        db.commit()


app.include_router(auth.router)
app.include_router(soc.router)
app.include_router(reports.router)


@app.get("/health")
def health():
    return {"status": "healthy", "version": "2.0", "mode": "defensive-simulation"}
