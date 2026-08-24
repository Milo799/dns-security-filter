"""离线大名单自动更新（方案 A：服务内定时任务）测试。

覆盖：
- enabled_source_keys：仅"已导入且启用"的来源
- auto_update_once：成功更新、单来源失败隔离、非内置来源跳过、停用来源跳过
- interval_seconds：默认 24h、非法值回退、超范围钳制
- 配置热更新：/api/config 读写新字段、间隔范围校验
- 应用启动挂载后台任务（lifespan）
"""

import sys
import os

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "platform"))

from app.main import app  # noqa: E402
from app import threat_list  # noqa: E402
from app import auto_update  # noqa: E402
from app.db import db_cursor  # noqa: E402
from config import CONFIG  # noqa: E402


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def token(client):
    r = client.post("/api/auth/login", json={
        "username": "admin", "password": CONFIG.admin_initial_password,
    })
    assert r.status_code == 200
    return r.json()["data"]["token"]


def _h(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------- enabled_source_keys ----------------

def test_enabled_source_keys_only_enabled():
    threat_list.import_source("hagezi_ti", "a.com\n")
    threat_list.import_source("stevenblack", "b.com\n")
    threat_list.enable_source("stevenblack", False)   # 停用
    try:
        keys = threat_list.enabled_source_keys()
        assert "hagezi_ti" in keys
        assert "stevenblack" not in keys              # 停用不参与自动更新
    finally:
        threat_list.delete_source("hagezi_ti")
        threat_list.delete_source("stevenblack")


def test_enabled_source_keys_empty():
    assert threat_list.enabled_source_keys() == []


# ---------------- auto_update_once ----------------

def test_auto_update_once_success(monkeypatch):
    threat_list.import_source("hagezi_ti", "old.com\n")
    called = {}
    def fake_download(url, max_bytes=0, timeout_s=0):
        called[url] = True
        return "new.com\nnew2.org\n"
    monkeypatch.setattr(threat_list, "download", fake_download)
    try:
        res = threat_list.auto_update_once()
        assert res["hagezi_ti"]["ok"] is True
        assert res["hagezi_ti"]["imported"] == 2
        assert called.get(threat_list.SOURCES[0]["url"]) is True
        # 整源替换生效：旧条目已移除
        assert not threat_list.check_domain("old.com")
        assert threat_list.check_domain("new.com")
    finally:
        threat_list.delete_source("hagezi_ti")


def test_auto_update_once_failure_isolated(monkeypatch):
    threat_list.import_source("hagezi_ti", "a.com\n")
    threat_list.import_source("stevenblack", "b.com\n")

    def fake_download(url, max_bytes=0, timeout_s=0):
        if "stevenblack" in url.lower():
            raise RuntimeError("boom")
        return "ok.example\n"
    monkeypatch.setattr(threat_list, "download", fake_download)
    try:
        res = threat_list.auto_update_once()
        assert res["hagezi_ti"]["ok"] is True
        assert res["stevenblack"]["ok"] is False
        assert "boom" in res["stevenblack"]["error"]
    finally:
        threat_list.delete_source("hagezi_ti")
        threat_list.delete_source("stevenblack")


def test_auto_update_once_skips_custom_and_disabled(monkeypatch):
    """非内置来源（custom）与停用来源不参与自动更新。"""
    threat_list.import_source("custom", "c.com\n")
    threat_list.import_source("hagezi_ult", "d.com\n")
    threat_list.enable_source("hagezi_ult", False)
    monkeypatch.setattr(threat_list, "download",
                        lambda url, max_bytes=0, timeout_s=0: "x.com\n")
    try:
        res = threat_list.auto_update_once()
        assert res == {}                        # 无内置启用来源 → 无动作
        assert threat_list.check_domain("c.com")  # custom 数据保留
    finally:
        threat_list.delete_source("custom")
        threat_list.delete_source("hagezi_ult")


# ---------------- interval_seconds ----------------

def test_interval_seconds_default():
    old = getattr(CONFIG, "threatlist_auto_interval_hours", 24)
    CONFIG.threatlist_auto_interval_hours = old
    assert auto_update.interval_seconds() == max(1, min(int(old), 720)) * 3600


def test_interval_seconds_invalid_fallback(monkeypatch):
    monkeypatch.setattr(CONFIG, "threatlist_auto_interval_hours", "abc")
    assert auto_update.interval_seconds() == 24 * 3600
    monkeypatch.setattr(CONFIG, "threatlist_auto_interval_hours", None)
    assert auto_update.interval_seconds() == 24 * 3600


def test_interval_seconds_clamped(monkeypatch):
    monkeypatch.setattr(CONFIG, "threatlist_auto_interval_hours", 0)
    assert auto_update.interval_seconds() == 1 * 3600
    monkeypatch.setattr(CONFIG, "threatlist_auto_interval_hours", 100000)
    assert auto_update.interval_seconds() == 720 * 3600


# ---------------- Web API 配置热更新 ----------------

def test_config_update_auto_keys(client, token):
    r = client.put("/api/config", json={
        "threatlist_auto_update": True,
        "threatlist_auto_interval_hours": 6,
    }, headers=_h(token))
    assert r.status_code == 200
    assert r.json()["data"]["updated"]["threatlist_auto_update"] is True

    r = client.get("/api/config", headers=_h(token))
    items = r.json()["data"]["items"]
    assert items["threatlist_auto_update"]["value"] == "1"
    assert items["threatlist_auto_interval_hours"]["value"] == "6"
    # 热生效到内存 CONFIG
    assert CONFIG.threatlist_auto_update is True
    assert CONFIG.threatlist_auto_interval_hours == 6

    # 恢复默认，避免影响其他测试
    client.put("/api/config", json={
        "threatlist_auto_update": False,
        "threatlist_auto_interval_hours": 24,
    }, headers=_h(token))


def test_config_interval_range_rejected(client, token):
    r = client.put("/api/config",
                   json={"threatlist_auto_interval_hours": 0},
                   headers=_h(token))
    assert r.status_code == 400
    r = client.put("/api/config",
                   json={"threatlist_auto_interval_hours": 9999},
                   headers=_h(token))
    assert r.status_code == 400


# ---------------- lifespan 挂载 ----------------

def test_startup_creates_auto_update_task(client):
    task = getattr(app.state, "threatlist_auto_task", None)
    assert task is not None and not task.done()
