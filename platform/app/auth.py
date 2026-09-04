"""JWT 认证（PRD 7.2：除 /api/auth/login 外均需 Bearer Token）。

迭代 31 新增：修改密码（强度校验 + must_change 标记闭环）。
"""

import re
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Header

from config import CONFIG
from app.db import db_cursor

# 弱密码黑名单（小写比对；管理界面单账号场景下的基础防线）
_WEAK_PASSWORDS = {"admin123", "password", "password123", "12345678",
                   "admin888", "admin666", "123456789", "qwerty123", "88888888", "66666666"}


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


def get_must_change(username: str) -> bool:
    """该账号是否处于"必须修改密码"状态（must_change 标记或仍在用初始密码）。"""
    with db_cursor() as cur:
        cur.execute(
            "SELECT password_hash, must_change FROM admin_user WHERE username=?",
            (username,),
        )
        row = cur.fetchone()
    if not row:
        return False
    if row["must_change"]:
        return True
    # 双保险：老库无标记，但登录密码就是初始密码 → 同样必须改
    # （生产 admin123 弱口令由此自动覆盖，无需存量迁移）
    return verify_password(CONFIG.admin_initial_password, row["password_hash"])


def validate_password_strength(new_password: str, username: str = "") -> str:
    """新密码强度校验；通过返回规范化值（去首尾空白），不通过抛 400。"""
    pwd = (new_password or "").strip()
    if len(pwd) < 8:
        raise HTTPException(status_code=400, detail="新密码长度至少 8 位")
    if len(pwd) > 128:
        raise HTTPException(status_code=400, detail="新密码长度至多 128 位")
    if not re.search(r"[A-Za-z]", pwd) or not re.search(r"[0-9]", pwd):
        raise HTTPException(
            status_code=400, detail="新密码须同时包含字母和数字")
    if pwd.lower() in _WEAK_PASSWORDS:
        raise HTTPException(
            status_code=400, detail="新密码过于常见（弱密码黑名单），请换一个")
    if username and pwd == username:
        raise HTTPException(status_code=400, detail="新密码不能与用户名相同")
    return pwd


def change_password(username: str, old_password: str, new_password: str) -> None:
    """修改密码：旧密码验证 + 新密码强度校验 + 落库（含 must_change 清零）。

    任何一步失败抛 400（旧密码错误不给模糊提示之外的信息）。
    成功后审计（含密码最后修改时间）、账号闸计数同步清零。
    """
    if not authenticate(username, old_password):
        raise HTTPException(status_code=400, detail="旧密码错误")
    if old_password == new_password:
        raise HTTPException(
            status_code=400, detail="新密码不能与旧密码相同")
    pwd = validate_password_strength(new_password, username)
    with db_cursor() as cur:
        cur.execute(
            "SELECT id FROM admin_user WHERE username=?", (username,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=400, detail="账号不存在")
        cur.execute(
            """UPDATE admin_user
               SET password_hash=?, must_change=0,
                   password_changed_at=datetime('now','localtime')
               WHERE username=?""",
            (hash_password(pwd), username),
        )
    # 改密成功：清账号闸（新凭据，旧失败计数不再相关）
    from app import login_guard
    login_guard.record_success(username, "")


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
