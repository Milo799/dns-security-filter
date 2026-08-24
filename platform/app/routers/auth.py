"""认证接口：登录 / 登出（PRD 7.2）。"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.auth import authenticate, create_token

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginBody(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(body: LoginBody):
    if not authenticate(body.username, body.password):
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    return {"code": 0, "message": "ok",
            "data": {"token": create_token(body.username)}}


@router.post("/logout")
def logout():
    # 无状态 JWT：前端丢弃 Token 即可；如需服务端注销可引入黑名单（后续扩展）
    return {"code": 0, "message": "ok", "data": {}}
