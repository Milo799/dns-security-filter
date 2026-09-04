"""迭代 31 · 认证安全批次测试。

覆盖：修改密码（旧密码验证/强度校验/审计/must_change 清零）、首次登录
强制改密标记（新库 seed 标记 + 初始密码比对双保险）、防爆破双闸
（账号锁定/IP 封禁/正确密码锁定不放行/计数重置/guard-stats）、
配置热生效（login_* 键写库 + CONFIG 生效）。

时间处理：账号锁/IP 封禁剩余时长用 monkeypatch time.monotonic 前进，
不真实等待。
"""

import sys
import os
import time

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "platform"))

from app.main import app  # noqa: E402
from app import login_guard  # noqa: E402
from app.db import db_cursor  # noqa: E402
from app.auth import hash_password  # noqa: E402
from config import CONFIG  # noqa: E402

INITIAL = CONFIG.admin_initial_password
NEW_PWD = "N3wSecure9"


@pytest.fixture()
def client():
    with TestClient(app) as c:   # 触发 startup：建表 + seed + 配置同步
        yield c


@pytest.fixture(autouse=True)
def _guard_reset():
    """每个测试前后清空防爆破内存计数（测试间互不串扰）。"""
    login_guard.reset()
    yield
    login_guard.reset()


@pytest.fixture(autouse=True)
def _restore_admin_password():
    """密码状态恢复：每个测试前把 admin 密码重置为初始密码、标记 must_change。

    改密类测试会永久修改 admin 密码（同一临时库跨测试共享），不恢复会
    串扰后续测试的 token fixture（401）。恢复 hash 直接复用 seed 逻辑。
    """
    with db_cursor() as cur:
        cur.execute("DELETE FROM admin_user WHERE username='admin'")
        cur.execute(
            "INSERT INTO admin_user (username, password_hash, must_change) "
            "VALUES (?, ?, 0)",
            ("admin", hash_password(INITIAL)),
        )
    yield
    # 收尾同样恢复（供下一测试的 setup 使用）


@pytest.fixture()
def token(client):
    r = client.post("/api/auth/login", json={
        "username": "admin", "password": INITIAL})
    assert r.status_code == 200
    return r.json()["data"]["token"]


def _h(token):
    return {"Authorization": f"Bearer {token}"}


# ================= A · 修改密码 =================

def test_change_password_full_cycle(client):
    """完整闭环：置 must_change → 登录(带标记) → 改密 → 新密码登录(无标记)。

    新库 seed 打标记的路径由 seed.init_admin 覆盖（INSERT 带 must_change=1）；
    本测试显式置 1 验证闭环（fixture 恢复时置 0）。"""
    with db_cursor() as cur:
        cur.execute("UPDATE admin_user SET must_change=1 WHERE username='admin'")
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": INITIAL})
    assert r.status_code == 200
    assert r.json()["data"]["must_change_password"] is True   # 标记生效

    r = client.post("/api/auth/change-password",
                    json={"old_password": INITIAL, "new_password": NEW_PWD},
                    headers=_h(r.json()["data"]["token"]))
    assert r.status_code == 200
    assert r.json()["data"]["relogin_required"] is True

    # 旧密码不再可用
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": INITIAL})
    assert r.status_code == 401
    # 新密码登录：无 must_change 标记
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": NEW_PWD})
    assert r.status_code == 200
    assert "must_change_password" not in r.json()["data"]

    # DB 标记清零 + 改密时间落库
    with db_cursor() as cur:
        row = cur.execute(
            "SELECT must_change, password_changed_at FROM admin_user "
            "WHERE username='admin'").fetchone()
    assert row["must_change"] == 0
    assert row["password_changed_at"]


def test_change_password_wrong_old(client, token):
    r = client.post("/api/auth/change-password",
                    json={"old_password": "wrong-old", "new_password": NEW_PWD},
                    headers=_h(token))
    assert r.status_code == 400
    assert "旧密码错误" in r.json()["detail"]
    # 密码未变：原密码仍可登录
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": INITIAL})
    assert r.status_code == 200


def test_change_password_same_as_old(client, token):
    r = client.post("/api/auth/change-password",
                    json={"old_password": INITIAL, "new_password": INITIAL},
                    headers=_h(token))
    assert r.status_code == 400


@pytest.mark.parametrize("pwd,expect_detail", [
    ("Ab1", "至少 8 位"),
    ("abcdefgh", "包含字母和数字"),      # 纯字母
    ("12345678", "包含字母和数字"),      # 纯数字
    ("admin123", "与旧密码相同"),        # admin123 恰为初始密码，旧密码相同检查先拦
    ("password123", "弱密码"),
    ("123456789", "包含字母和数字"),     # 纯数字检查先于弱密码黑名单
    ("qwerty123", "弱密码"),             # 字母+数字齐但属弱密码黑名单
])
def test_change_password_strength(client, token, pwd, expect_detail):
    r = client.post("/api/auth/change-password",
                    json={"old_password": INITIAL, "new_password": pwd},
                    headers=_h(token))
    assert r.status_code == 400
    assert expect_detail in r.json()["detail"]


def test_change_password_audited(client, token):
    client.post("/api/auth/change-password",
                json={"old_password": INITIAL, "new_password": NEW_PWD},
                headers=_h(token))
    with db_cursor() as cur:
        row = cur.execute(
            "SELECT operator, action, detail FROM audit_log "
            "WHERE action='password_change' ORDER BY id DESC").fetchone()
    assert row is not None
    assert row["operator"] == "admin"
    assert "admin" in row["detail"]
    assert NEW_PWD not in row["detail"]   # 审计不含新密码明文
    assert INITIAL not in row["detail"]   # 也不含旧密码


def test_change_password_requires_token(client):
    r = client.post("/api/auth/change-password",
                    json={"old_password": INITIAL, "new_password": NEW_PWD})
    assert r.status_code == 401


# ================= B · 首次登录强制改密（双保险） =================

def test_must_change_via_initial_password_match(client):
    """老库场景：must_change 标记不存在（0），但密码仍是初始密码 →
    登录响应同样带 must_change_password（get_must_change 双保险）。"""
    with db_cursor() as cur:
        cur.execute("UPDATE admin_user SET must_change=0 WHERE username='admin'")
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": INITIAL})
    assert r.status_code == 200
    assert r.json()["data"]["must_change_password"] is True


def test_must_change_cleared_after_change(client, token):
    client.post("/api/auth/change-password",
                json={"old_password": INITIAL, "new_password": NEW_PWD},
                headers=_h(token))
    # 标记清零后即使把密码改回初始密码形态，登录才重新触发（语义合理）
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": NEW_PWD})
    assert r.status_code == 200
    assert "must_change_password" not in r.json()["data"]


# ================= C · 防爆破：账号闸 =================

def test_account_lockout_after_threshold(client, monkeypatch):
    thr = CONFIG.login_lockout_threshold
    for i in range(thr - 1):
        r = client.post("/api/auth/login",
                        json={"username": "admin", "password": "bad-" + str(i)})
        assert r.status_code == 401
    # 第 thr 次失败触发锁定
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": "bad-final"})
    assert r.status_code == 401
    assert "锁定" in r.json()["detail"]

    # 锁定期间：正确密码也不放行（429）
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": INITIAL})
    assert r.status_code == 429
    assert "锁定" in r.json()["detail"]


def test_account_lockout_expires(client, monkeypatch):
    thr = CONFIG.login_lockout_threshold
    for _ in range(thr):
        client.post("/api/auth/login",
                    json={"username": "admin", "password": "bad"})
    assert client.post("/api/auth/login",
                       json={"username": "admin", "password": INITIAL}
                       ).status_code == 429
    # 时间前进越过锁定时长（固定基准值，勿引用已被替换的 time.monotonic）
    _base = time.monotonic()
    monkeypatch.setattr(time, "monotonic", lambda: _base + 1e9 + 3600)
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": INITIAL})
    assert r.status_code == 200   # 解锁 + 计数归零，正常登录


def test_account_lockout_audit_written(client):
    thr = CONFIG.login_lockout_threshold
    for _ in range(thr):
        client.post("/api/auth/login",
                    json={"username": "admin", "password": "bad"})
    with db_cursor() as cur:
        row = cur.execute(
            "SELECT action, detail FROM audit_log "
            "WHERE action='login_lockout' ORDER BY id DESC").fetchone()
    assert row is not None
    assert "admin" in row["detail"]


def test_success_resets_account_counter(client):
    """失败 thr-1 次后成功登录 → 计数清零，再失败 thr-1 次不锁定。"""
    thr = CONFIG.login_lockout_threshold
    for _ in range(thr - 1):
        client.post("/api/auth/login",
                    json={"username": "admin", "password": "bad"})
    assert client.post("/api/auth/login",
                       json={"username": "admin", "password": INITIAL}
                       ).status_code == 200
    for _ in range(thr - 1):
        client.post("/api/auth/login",
                    json={"username": "admin", "password": "bad"})
    # 未达累计阈值：正确密码仍可登录（未锁定）
    assert client.post("/api/auth/login",
                       json={"username": "admin", "password": INITIAL}
                       ).status_code == 200


def test_account_lockout_disabled_when_threshold_zero(client):
    """阈值=0 禁用账号闸（逃生开关）。"""
    old = CONFIG.login_lockout_threshold
    CONFIG.login_lockout_threshold = 0
    try:
        for _ in range(10):
            r = client.post("/api/auth/login",
                            json={"username": "admin", "password": "bad"})
            assert r.status_code == 401   # 永不 429
        r = client.post("/api/auth/login",
                        json={"username": "admin", "password": INITIAL})
        assert r.status_code == 200
    finally:
        CONFIG.login_lockout_threshold = old


# ================= C · 防爆破：IP 闸 =================

def test_ip_block_after_window_failures(client):
    """IP 闸：同 IP 累计失败达阈值 → 429 封禁（TestClient 同源 IP）。

    注意：账号闸在 authenticate 之前前置拦截（429 不计失败），所以本测试
    用递增用户名错开账号闸（每用户名只失败 1 次），让 20 次失败全部落到
    IP 闸计数上——这也正是 IP 闸的设计场景（换账号字典攻击）。
    """
    ip_thr = CONFIG.login_ip_threshold
    for i in range(ip_thr):
        client.post("/api/auth/login",
                    json={"username": f"user{i}", "password": "bad"})
    # 已封禁：任意用户名直接 429（IP 前置闸）
    r = client.post("/api/auth/login",
                    json={"username": "anyone", "password": "bad-more"})
    assert r.status_code == 429
    assert "封禁" in r.json()["detail"]


def test_ip_block_audit_written(client):
    ip_thr = CONFIG.login_ip_threshold
    for i in range(ip_thr):
        client.post("/api/auth/login",
                    json={"username": f"user{i}", "password": "bad"})
    with db_cursor() as cur:
        row = cur.execute(
            "SELECT action FROM audit_log WHERE action='login_ip_block'"
        ).fetchone()
    assert row is not None


# ================= 观测与配置 =================

def test_guard_stats_endpoint(client, token):
    r = client.get("/api/auth/guard-stats", headers=_h(token))
    assert r.status_code == 200
    data = r.json()["data"]
    assert "locked_accounts" in data and "blocked_ips" in data

    # 触发一次锁定后再查
    thr = CONFIG.login_lockout_threshold
    for _ in range(thr):
        client.post("/api/auth/login",
                    json={"username": "admin", "password": "bad"})
    r = client.get("/api/auth/guard-stats", headers=_h(token))
    locked = r.json()["data"]["locked_accounts"]
    assert any(a["username"] == "admin" for a in locked)


def test_login_params_config_hot_update(client, token):
    """login_* 配置经 /api/config 写库 + CONFIG 热生效。"""
    original = CONFIG.login_lockout_threshold
    try:
        r = client.put("/api/config", json={"login_lockout_threshold": 2},
                       headers=_h(token))
        assert r.status_code == 200
        assert CONFIG.login_lockout_threshold == 2
        # 新阈值立即生效：2 次失败即锁定
        client.post("/api/auth/login",
                    json={"username": "admin", "password": "bad"})
        r = client.post("/api/auth/login",
                        json={"username": "admin", "password": "bad"})
        assert r.status_code == 401 and "锁定" in r.json()["detail"]
        r = client.post("/api/auth/login",
                        json={"username": "admin", "password": "bad"})
        assert r.status_code == 429
    finally:
        # 恢复默认（写库 + CONFIG，防串扰后续测试）
        client.put("/api/config",
                   json={"login_lockout_threshold": original},
                   headers=_h(token))
        assert CONFIG.login_lockout_threshold == original


def test_login_params_validation(client, token):
    r = client.put("/api/config", json={"login_lockout_minutes": 0},
                   headers=_h(token))
    assert r.status_code == 400
    r = client.put("/api/config", json={"login_ip_threshold": -1},
                   headers=_h(token))
    assert r.status_code == 400


# ================= 存量库迁移 =================

def test_admin_user_columns_migrated(client):
    """迭代 31 新列存在（新库直接建、老库 ALTER 补齐——本测试走新库路径，
    迁移路径由 db._migrate 覆盖，此处验证列可写可读）。"""
    with db_cursor() as cur:
        cols = {r["name"] for r in cur.execute(
            "PRAGMA table_info(admin_user)").fetchall()}
        assert "must_change" in cols
        assert "password_changed_at" in cols
        # 直接 SQL 更新标记（模拟老库管理员置位）
        cur.execute("UPDATE admin_user SET must_change=1 WHERE username='admin'")
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": INITIAL})
    assert r.json()["data"]["must_change_password"] is True


def test_must_change_via_verify_fallback_for_old_db(client):
    """极端场景：老库 hash 与初始密码相同但 must_change 列为 0 →
    get_must_change 的初始密码比对兜底触发（B 方案双保险的第二路）。"""
    with db_cursor() as cur:
        cur.execute("UPDATE admin_user SET must_change=0 WHERE username='admin'")
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": INITIAL})
    assert r.json()["data"].get("must_change_password") is True
