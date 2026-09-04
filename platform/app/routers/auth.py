"""认证接口：登录 / 登出 / 修改密码（PRD 7.2 + 迭代 31）。

迭代 31 改造：
- login 集成防爆破双闸（账号锁定 + IP 封禁，见 app/login_guard.py）
  与 must_change 检测（首次登录/初始密码 → 响应标记，前端强制改密）；
- 新增 POST /api/auth/change-password（旧密码验证 + 强度校验 + 审计）；
- 新增 GET /api/auth/guard-stats（锁定/封禁观测）。
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.auth import (
    authenticate, create_token, change_password, get_current_user,
    get_must_change,
)
from app import login_guard
from app.audit import write_audit

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginBody(BaseModel):
    username: str
    password: str


class ChangePasswordBody(BaseModel):
    old_password: str
    new_password: str


def _client_ip(request: Request) -> str:
    """来源 IP（直连部署无反代，取 socket 层即可）。"""
    client = request.client
    return client.host if client else ""


@router.post("/login")
def login(body: LoginBody, request: Request):
    ip = _client_ip(request)

    # ① IP 闸前置：封禁中的 IP 直接拒绝（含正确密码）
    blocked, remain = login_guard.ip_status(ip)
    if blocked:
        raise HTTPException(
            status_code=429,
            detail=f"来源 IP 已被临时封禁（尝试登录失败次数过多），"
                   f"剩余 {max(remain // 60, 1)} 分钟")

    # ② 账号闸前置：锁定中的账号直接拒绝（含正确密码）
    locked, remain = login_guard.account_status(body.username)
    if locked:
        raise HTTPException(
            status_code=429,
            detail=f"账号已临时锁定（连续登录失败），"
                   f"剩余 {max(remain // 60, 1)} 分钟")

    if not authenticate(body.username, body.password):
        # ③ 失败累计双闸计数（达到阈值触发锁定/封禁并写审计）
        triggered = login_guard.record_failure(body.username, ip)
        detail = "用户名或密码错误"
        if triggered.get("account_locked"):
            detail += f"；账号已锁定 {_mins(triggered['account_lock_seconds'])} 分钟"
        elif triggered.get("ip_blocked"):
            detail += f"；来源 IP 已封禁 {_mins(triggered['ip_block_seconds'])} 分钟"
        raise HTTPException(status_code=401, detail=detail)

    # ④ 成功：清账号闸计数；检测是否必须修改密码
    login_guard.record_success(body.username, ip)
    data = {"token": create_token(body.username)}
    must_change = get_must_change(body.username)
    if must_change:
        data["must_change_password"] = True
    return {"code": 0, "message": "ok", "data": data}


def _mins(seconds: int) -> int:
    return max(seconds // 60, 1)


@router.post("/change-password")
def change_password_ep(body: ChangePasswordBody,
                       user: str = Depends(get_current_user)):
    """修改当前登录账号密码；成功写审计并要求前端重新登录。"""
    change_password(user, body.old_password, body.new_password)
    write_audit(user, "password_change", {"username": user})
    return {"code": 0, "message": "ok",
            "data": {"relogin_required": True}}


@router.get("/guard-stats")
def guard_stats_ep(_: str = Depends(get_current_user)):
    """防爆破观测：当前锁定账号与封禁 IP 快照。"""
    return {"code": 0, "message": "ok", "data": login_guard.guard_stats()}


@router.post("/logout")
def logout():
    # 无状态 JWT：前端丢弃 Token 即可；如需服务端注销可引入黑名单（后续扩展）
    return {"code": 0, "message": "ok", "data": {}}
