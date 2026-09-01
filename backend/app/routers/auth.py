from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AuditLog, User
from ..schemas import LoginRequest, TokenResponse, UserOut
from ..security import create_token, current_user, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == body.username))
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    db.add(AuditLog(username=user.username, action="LOGIN", detail=f"role={user.role}"))
    db.commit()
    return TokenResponse(access_token=create_token(user), role=user.role)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user
