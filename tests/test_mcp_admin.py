"""MCP Web 管理接口测试（迭代 51：写开关 + Token 轮换）。

覆盖 app/routers/mcp.py 新增的三个端点：
  GET  /api/mcp/admin        → 状态查询（token 脱敏）
  POST /api/mcp/admin/write  → 写能力开关（需 confirm、失败回滚、写审计）
  POST /api/mcp/admin/token  → Token 轮换（新 token 只返回一次、写审计）

测试手法：
  - DNSF_MCP_ENV_FILE 指向 pytest 临时 env 文件（不碰 /etc/dnsfilter/）；
  - DNSF_MCP_SYSTEMCTL 指向 fake systemctl 脚本（不真重启服务），
    通过 DNSF_FAKE_SYSTEMCTL_FAIL 控制失败场景（验证回滚路径）。
"""

import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "platform"))


# ---- fake systemctl：避免测试真去重启机器上的服务 -----------------------
# 用 Python 脚本（跨平台，Windows 无法直接执行 bash）

FAKE_SYSTEMCTL = '''import os, sys
args = sys.argv[1:]
if "restart" in args and os.environ.get("DNSF_FAKE_SYSTEMCTL_FAIL", "0") == "1":
    print("fake restart failure (test)", file=sys.stderr)
    sys.exit(1)
if "is-active" in args or "show" in args:
    print("active")
sys.exit(0)
'''


@pytest.fixture()
def mcp_env(tmp_path, monkeypatch):
    """临时 mcp.env + fake systemctl，返回 env 文件路径。"""
    env_file = tmp_path / "mcp.env"
    env_file.write_text(
        "# DNS 安全过滤 · MCP 服务环境\n"
        "DNSF_API_BASE=http://127.0.0.1:8080\n"
        "DNSF_API_USER=admin\n"
        "DNSF_API_PASSWORD=secret-pass\n"
        "DNSF_MCP_TRANSPORT=http\n"
        "DNSF_MCP_HOST=0.0.0.0\n"
        "DNSF_MCP_PORT=8090\n"
        f"DNSF_MCP_TOKEN=OldToken_{('x' * 30)}\n"
        "DNSF_MCP_ALLOW_WRITE=0\n"
        "DNSF_MCP_AGENT=agent\n",
        encoding="utf-8",
    )
    fake_ctl = tmp_path / "fake_systemctl.py"
    fake_ctl.write_text(FAKE_SYSTEMCTL, encoding="utf-8")

    import sys as _sys
    monkeypatch.setenv("DNSF_MCP_ENV_FILE", str(env_file))
    monkeypatch.setenv("DNSF_MCP_SERVICE", "dnsfilter-mcp-test")
    # mcp router 用模块级常量取 env 路径，需 patch 模块属性
    import app.routers.mcp as mcp_mod
    monkeypatch.setattr(mcp_mod, "_ENV_PATH", str(env_file))
    monkeypatch.setattr(mcp_mod, "_SERVICE", "dnsfilter-mcp-test")
    # Windows/测试机直接执行 fake 脚本（用 python 调起，跨平台）。
    # _ctl_argv 在 root 直连、非 root 加 sudo——测试环境不适用，
    # 统一 patch 成 fake 脚本两段式调用。
    monkeypatch.setattr(mcp_mod, "_SYSTEMCTL", str(fake_ctl))
    real_run = subprocess.run

    def _patched_run(args, **kw):
        if args and str(args[0]) == str(fake_ctl):
            return real_run([_sys.executable, str(fake_ctl)] + list(args[1:]),
                            **kw)
        return real_run(args, **kw)

    monkeypatch.setattr("app.routers.mcp.subprocess.run", _patched_run)

    # 非 root 环境下 _ctl_argv 会加 sudo 前缀；测试直接返回 fake 路径
    monkeypatch.setattr(mcp_mod, "_ctl_argv",
                        lambda *a: [str(fake_ctl)] + list(a))
    yield str(env_file)
    os.environ.pop("DNSF_FAKE_SYSTEMCTL_FAIL", None)


@pytest.fixture()
def client(mcp_env):
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def token(client):
    from config import CONFIG
    r = client.post("/api/auth/login", json={
        "username": "admin", "password": CONFIG.admin_initial_password})
    assert r.status_code == 200
    return r.json()["data"]["token"]


def _h(token):
    return {"Authorization": f"Bearer {token}"}


def _read_env_kv(path):
    kv = {}
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
    return kv


# ---------------- 状态查询 ----------------

def test_admin_status_returns_masked_token(client, token, mcp_env):
    r = client.get("/api/mcp/admin", headers=_h(token))
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["running"] is True
    assert d["allow_write"] is False          # 初始 0
    assert d["token_masked"].startswith("OldT")
    assert d["token_masked"].endswith("xxxxx"[:5]) or "*" in d["token_masked"]
    assert "*" in d["token_masked"]           # 必须脱敏
    assert "OldToken_" not in d["token_masked"] or d["token_masked"] == "OldT" + "*"*30
    # 完整 token 绝不能出现在响应里
    full = _read_env_kv(mcp_env)["DNSF_MCP_TOKEN"]
    assert full not in r.text


def test_admin_status_requires_auth(client):
    r = client.get("/api/mcp/admin")
    assert r.status_code == 401


def test_admin_status_env_missing(client, token, monkeypatch, tmp_path):
    import app.routers.mcp as mcp_mod
    monkeypatch.setattr(mcp_mod, "_ENV_PATH", str(tmp_path / "nope.env"))
    r = client.get("/api/mcp/admin", headers=_h(token))
    assert r.json()["code"] == 1


# ---------------- 写能力开关 ----------------

def test_write_toggle_needs_confirm(client, token):
    r = client.post("/api/mcp/admin/write",
                    headers=_h(token), json={"enabled": True})
    assert r.json()["code"] == 2
    assert "confirm" in r.json()["message"]


def test_write_toggle_on_persists_and_audits(client, token, mcp_env):
    r = client.post("/api/mcp/admin/write",
                    headers=_h(token), json={"enabled": True, "confirm": True})
    assert r.json()["code"] == 0
    d = r.json()["data"]
    assert d["changed"] is True
    assert d["allow_write"] is True
    # env 文件已更新
    kv = _read_env_kv(mcp_env)
    assert kv["DNSF_MCP_ALLOW_WRITE"] == "1"
    # 注释行保留（原子替换不丢内容）
    content = open(mcp_env, encoding="utf-8").read()
    assert "MCP 服务环境" in content
    # 审计已记录
    r2 = client.get("/api/audit?size=10", headers=_h(token))
    actions = [it.get("action") for it in r2.json()["data"]["items"]]
    assert "mcp_admin_write" in actions


def test_write_toggle_off(client, token, mcp_env):
    # 先开
    client.post("/api/mcp/admin/write", headers=_h(token),
                json={"enabled": True, "confirm": True})
    # 再关
    r = client.post("/api/mcp/admin/write", headers=_h(token),
                    json={"enabled": False, "confirm": True})
    assert r.json()["code"] == 0
    kv = _read_env_kv(mcp_env)
    assert kv["DNSF_MCP_ALLOW_WRITE"] == "0"


def test_write_toggle_noop_when_same(client, token, mcp_env):
    r = client.post("/api/mcp/admin/write", headers=_h(token),
                    json={"enabled": False, "confirm": True})
    assert r.json()["code"] == 0
    assert r.json()["data"]["changed"] is False


def test_write_toggle_rollback_on_restart_failure(
        client, token, mcp_env, monkeypatch):
    monkeypatch.setenv("DNSF_FAKE_SYSTEMCTL_FAIL", "1")
    r = client.post("/api/mcp/admin/write", headers=_h(token),
                    json={"enabled": True, "confirm": True})
    assert r.json()["code"] == 3
    assert "回滚" in r.json()["message"]
    # env 已回滚
    kv = _read_env_kv(mcp_env)
    assert kv["DNSF_MCP_ALLOW_WRITE"] == "0"


# ---------------- Token 轮换 ----------------

def test_token_rotate_returns_new_once(client, token, mcp_env):
    old = _read_env_kv(mcp_env)["DNSF_MCP_TOKEN"]
    r = client.post("/api/mcp/admin/token", headers=_h(token),
                    json={"confirm": True})
    assert r.json()["code"] == 0
    new = r.json()["data"]["token"]
    assert new and new != old and len(new) >= 32
    # env 已更新
    assert _read_env_kv(mcp_env)["DNSF_MCP_TOKEN"] == new
    # 再查状态：只给脱敏，不给完整值
    r2 = client.get("/api/mcp/admin", headers=_h(token))
    assert new not in r2.text
    assert r2.json()["data"]["token_masked"].startswith(new[:4])


def test_token_rotate_needs_confirm(client, token):
    r = client.post("/api/mcp/admin/token", headers=_h(token), json={})
    assert r.json()["code"] == 2


def test_token_rotate_audits_without_leak(client, token, mcp_env):
    r = client.post("/api/mcp/admin/token", headers=_h(token),
                    json={"confirm": True})
    new = r.json()["data"]["token"]
    # 审计里只有脱敏形式
    r2 = client.get("/api/audit?size=10", headers=_h(token))
    audit_text = str(r2.json()["data"]["items"])
    assert new not in audit_text
    assert "mcp_admin_token" in audit_text


def test_token_rotate_rollback_on_failure(client, token, mcp_env, monkeypatch):
    old = _read_env_kv(mcp_env)["DNSF_MCP_TOKEN"]
    monkeypatch.setenv("DNSF_FAKE_SYSTEMCTL_FAIL", "1")
    r = client.post("/api/mcp/admin/token", headers=_h(token),
                    json={"confirm": True})
    assert r.json()["code"] == 3
    assert _read_env_kv(mcp_env)["DNSF_MCP_TOKEN"] == old
