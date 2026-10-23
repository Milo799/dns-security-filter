"""MCP 服务支撑接口（迭代 50 + 迭代 51：Web 端 MCP 管理）。

MCP 服务（platform/mcp_server.py）本身不直连数据库，所有写操作都经本
平台的既有 API 执行（复用鉴权/校验/审计/缓存失效）。

本路由两类职责：

一、审计归属（迭代 50）：把"这次改动是哪个 Agent 发起、用哪个 MCP 工具"
   记到平台审计里——否则审计里只能看到 admin 账号，无法区分人与 Agent。
   安全说明：operator 由调用方声明（需管理员 token）。它只影响审计归属
   展示，不改变任何权限——能调用本接口的账号本就有等价写权限。

二、Web 端 MCP 管理（迭代 51，用户 2026-10-23 需求）：
   - GET  /api/mcp/admin        → 服务状态（运行/端口/写开关/token 脱敏）
   - POST /api/mcp/admin/write  → 开关写能力（写 mcp.env + 重启服务）
   - POST /api/mcp/admin/token  → 轮换 Bearer Token（生成新串 + 重启）

   实现方式：/etc/dnsfilter/mcp.env 是 systemd 与 MCP 共用的运行时配置，
   本路由直接读写该文件并 systemctl restart dnsfilter-mcp。
   mcp.env 与 platform-web 同机（生产 .191），本地文件操作即可，
   无需引入额外的配置存储。

   安全设计：
   - 所有端点需管理员登录（get_current_user），写操作逐条记审计；
   - token 只在"轮换响应"里完整返回一次（前端展示后即不再可得），
     GET 状态只给脱敏形式（前 4 后 4），避免日常查询泄露；
   - 重启失败自动回滚 env 变更并再次重启，保证服务始终可用；
   - 文件写入用原子替换（写临时文件 + os.replace），避免半写状态。
"""

import os
import re
import secrets
import shutil
import subprocess
import tempfile

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.audit import write_audit
from app.auth import get_current_user

router = APIRouter(prefix="/api/mcp", tags=["mcp"])


# ── 迭代 50：审计归属 ────────────────────────────────────────────────────


class McpAuditBody(BaseModel):
    tool: str = Field(min_length=1, max_length=64)
    detail: dict = Field(default_factory=dict)
    operator: str = Field(default="mcp:agent", max_length=64)


@router.post("/audit")
def mcp_audit(body: McpAuditBody, _: str = Depends(get_current_user)):
    """记录一次 MCP 工具操作（供审计追溯：谁、经哪个工具、改了什么）。"""
    tool = body.tool.strip().replace(" ", "_")[:64]
    operator = (body.operator or "mcp:agent").strip()[:64]
    write_audit(operator, "mcp_" + tool, body.detail or {})
    return {"code": 0, "message": "ok",
            "data": {"recorded": True, "operator": operator,
                     "action": "mcp_" + tool}}


# ── 迭代 51：Web 端 MCP 管理 ─────────────────────────────────────────────

# mcp.env 路径：环境变量可覆盖（测试用），默认生产位置
_ENV_PATH = os.environ.get("DNSF_MCP_ENV_FILE", "/etc/dnsfilter/mcp.env")
_SERVICE = os.environ.get("DNSF_MCP_SERVICE", "dnsfilter-mcp")
# systemctl 可执行路径（测试里 patch 成 fake 脚本）
_SYSTEMCTL = os.environ.get("DNSF_MCP_SYSTEMCTL", "systemctl")

_KEY_ALLOW = "DNSF_MCP_ALLOW_WRITE"
_KEY_TOKEN = "DNSF_MCP_TOKEN"
_KEY_PORT = "DNSF_MCP_PORT"
_KEY_HOST = "DNSF_MCP_HOST"
_KEY_AGENT = "DNSF_MCP_AGENT"


def _read_env(path: str | None = None) -> dict[str, str]:
    """读取 mcp.env 为 dict（KEY=VALUE 行，忽略注释与空行）。

    path=None 时用模块级 _ENV_PATH（运行时取，便于测试 patch）——
    不用默认参数直接绑定，那会在函数定义时冻结值。
    """
    if path is None:
        path = _ENV_PATH
    out: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def _write_env_atomic(values: dict[str, str], path: str | None = None) -> None:
    """原子更新 mcp.env：保留原注释与顺序，只改目标 KEY。

    写入临时文件后 os.replace 原子替换——避免写一半被 systemd 读到。
    """
    if path is None:
        path = _ENV_PATH
    lines: list[str] = []
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        lines = [f"# {os.path.basename(path)}"]

    seen: set[str] = set()
    new_lines: list[str] = []
    for ln in lines:
        stripped = ln.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k = stripped.split("=", 1)[0].strip()
            if k in values:
                new_lines.append(f"{k}={values[k]}")
                seen.add(k)
                continue
        new_lines.append(ln)
    # 原 env 里没有的 KEY 追加到末尾
    for k, v in values.items():
        if k not in seen:
            new_lines.append(f"{k}={v}")

    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".mcp-env-", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(new_lines) + "\n")
        # 保留原文件权限（600）
        try:
            shutil.copystat(path, tmp)
        except OSError:
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _restart_service() -> tuple[bool, str]:
    """重启 dnsfilter-mcp，返回 (成功与否, 备注)。"""
    try:
        r = subprocess.run([_SYSTEMCTL, "restart", _SERVICE],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return False, (r.stderr or "restart 返回非零").strip()[:300]
        # 确认 active
        c = subprocess.run([_SYSTEMCTL, "is-active", _SERVICE],
                           capture_output=True, text=True, timeout=15)
        if (c.stdout or "").strip() != "active":
            return False, f"重启后状态异常：{(c.stdout or '').strip()}"
        return True, "active"
    except FileNotFoundError:
        return False, "本机无 systemctl（非生产部署形态，仅文件已更新）"
    except subprocess.TimeoutExpired:
        return False, "restart 超时（60s）"


def _mask(token: str) -> str:
    """token 脱敏：前 4 + 后 4，中间星号。"""
    if not token:
        return ""
    if len(token) <= 8:
        return "*" * len(token)
    return token[:4] + "*" * (len(token) - 8) + token[-4:]


def _service_status() -> dict:
    """查询 systemd 服务状态（best effort）。"""
    out = {"running": None, "since": ""}
    try:
        c = subprocess.run([_SYSTEMCTL, "is-active", _SERVICE],
                           capture_output=True, text=True, timeout=15)
        out["running"] = (c.stdout or "").strip() == "active"
        out["state"] = (c.stdout or "").strip()
        s = subprocess.run(
            [_SYSTEMCTL, "show", _SERVICE, "--property=ActiveEnterTimestamp",
             "--value"],
            capture_output=True, text=True, timeout=15)
        out["since"] = (s.stdout or "").strip()
    except Exception:
        pass
    return out


@router.get("/admin")
def mcp_admin_status(user: str = Depends(get_current_user)):
    """MCP 服务状态总览：运行状态 / 端点 / 写开关 / token 脱敏。

    token 只给脱敏形式——完整 token 仅在轮换时返回一次。
    """
    env = _read_env()
    if not env:
        return {"code": 1, "message": f"未找到 mcp.env（{_ENV_PATH}）——"
                "当前部署形态可能不在生产机上", "data": None}
    st = _service_status()
    token = env.get(_KEY_TOKEN, "")
    return {"code": 0, "message": "ok", "data": {
        "env_file": _ENV_PATH,
        "service": _SERVICE,
        "running": st.get("running"),
        "state": st.get("state", ""),
        "since": st.get("since", ""),
        "transport": env.get("DNSF_MCP_TRANSPORT", "http"),
        "endpoint": f"http://{env.get(_KEY_HOST, '0.0.0.0')}:"
                    f"{env.get(_KEY_PORT, '8090')}/mcp",
        "api_base": env.get("DNSF_API_BASE", ""),
        "agent_name": env.get(_KEY_AGENT, ""),
        "allow_write": env.get(_KEY_ALLOW, "0") == "1",
        "token_masked": _mask(token),
        "token_len": len(token),
    }}


class McpWriteBody(BaseModel):
    enabled: bool
    # 二次确认：前端必须传 confirm=true 才执行（防误触）
    confirm: bool = False


@router.post("/admin/write")
def mcp_admin_write(body: McpWriteBody, user: str = Depends(get_current_user)):
    """开关 MCP 写能力：写 mcp.env + 重启服务。失败自动回滚。"""
    if not body.confirm:
        return {"code": 2, "message": "需要二次确认：请带 confirm=true 重新调用",
                "data": {"enabled": body.enabled}}

    env = _read_env()
    if not env:
        return {"code": 1, "message": f"未找到 mcp.env（{_ENV_PATH}）", "data": None}

    old = env.get(_KEY_ALLOW, "0")
    new = "1" if body.enabled else "0"
    if old == new:
        return {"code": 0, "message": "无变化（写能力已是该状态）",
                "data": {"allow_write": new == "1", "changed": False}}

    _write_env_atomic({_KEY_ALLOW: new})
    ok, note = _restart_service()
    if not ok:
        # 回滚
        _write_env_atomic({_KEY_ALLOW: old})
        ok2, _ = _restart_service()
        write_audit(user, "mcp_admin_write",
                    {"from": old, "to": new, "result": "failed",
                     "reverted": True, "restart_error": note})
        return {"code": 3,
                "message": f"重启失败已回滚（{note}）",
                "data": {"allow_write": old == "1", "changed": False}}

    write_audit(user, "mcp_admin_write",
                {"from": old, "to": new, "result": "ok",
                 "service": _SERVICE})
    return {"code": 0, "message": "ok", "data": {
        "allow_write": new == "1", "changed": True,
        "service_note": note,
        "hint": "开启后 AI 写操作仍需用户逐条确认（confirm=true 二道闸门）"
                if new == "1" else "已恢复只读，所有写工具返回 write_disabled",
    }}


class McpTokenBody(BaseModel):
    confirm: bool = False


@router.post("/admin/token")
def mcp_admin_token(body: McpTokenBody, user: str = Depends(get_current_user)):
    """轮换 Bearer Token：生成新随机串 + 写 env + 重启。

    ⚠️ 新 token 只在本次响应里完整返回一次，请立即分发给使用者。
    """
    if not body.confirm:
        return {"code": 2, "message": "需要二次确认：请带 confirm=true 重新调用",
                "data": None}

    env = _read_env()
    if not env:
        return {"code": 1, "message": f"未找到 mcp.env（{_ENV_PATH}）", "data": None}

    old = env.get(_KEY_TOKEN, "")
    if not old:
        return {"code": 4, "message": "当前 mcp.env 无 token（非 http 部署形态？）",
                "data": None}

    new = secrets.token_urlsafe(32)
    _write_env_atomic({_KEY_TOKEN: new})
    ok, note = _restart_service()
    if not ok:
        _write_env_atomic({_KEY_TOKEN: old})
        _restart_service()
        write_audit(user, "mcp_admin_token",
                    {"result": "failed", "reverted": True,
                     "restart_error": note})
        return {"code": 3, "message": f"重启失败已回滚（{note}）", "data": None}

    write_audit(user, "mcp_admin_token",
                {"result": "ok", "old_masked": _mask(old),
                 "new_masked": _mask(new), "service": _SERVICE})
    return {"code": 0, "message": "ok", "data": {
        "token": new,                       # ⚠️ 唯一一次完整返回
        "token_masked": _mask(new),
        "service_note": note,
        "hint": "旧 token 已全部失效；新 token 请立即分发给使用者，"
                "本响应关闭后不再展示完整值",
    }}
