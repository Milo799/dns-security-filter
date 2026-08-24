"""JWT 认证（PRD 7.2：除 /api/auth/login 外均需 Bearer Token）。"""

from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Header

from config import CONFIG
from app.db import db_cursor


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def authenticate(username: str, password: str) -> bool:
    with db_cursor() as cur:
        cur.execute(
            "SELECT password_hash FROM admin_user WHERE username=?", (username,)
        )
        row = cur.fetchone()
    return bool(row and verify_password(password, row["password_hash"]))


def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.now(timezone.utc)
        + timedelta(minutes=CONFIG.web.jwt_expire_minutes),
    }
    return jwt.encode(payload, CONFIG.web.jwt_secret, algorithm="HS256")


def get_current_user(
    authorization: str | None = Header(default=None),
) -> str:
    """FastAPI 依赖：校验 Bearer Token，返回用户名；失败抛 401。"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="未认证")
    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = jwt.decode(token, CONFIG.web.jwt_secret, algorithms=["HS256"])
        return payload["sub"]
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token 无效或已过期")
