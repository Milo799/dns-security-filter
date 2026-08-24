"""测试中心 API 测试（黑白名单命中 + 情报源逐源结果 + 融合裁决）。

全部使用本地名单 / example 占位适配器（恒无结论），不依赖公网。
"""

import sys
import os

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "platform"))

from app.main import app  # noqa: E402
from app.db import db_cursor  # noqa: E402


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def token(client):
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": "admin123"})
    return r.json()["data"]["token"]


def _h(token):
    return {"Authorization": f"Bearer {token}"}


def _add_list(client, token, list_type, target, value):
    r = client.post("/api/list",
                    json={"list_type": list_type, "target": target,
                          "value": value, "enabled": True},
                    headers=_h(token))
    assert r.status_code == 200


# ---------------- 本地黑白名单 ----------------

def test_domain_blacklist_hit(client, token):
    _add_list(client, token, "blacklist", "domain", "evil.example.com")
    r = client.post("/api/test/domain",
                    json={"domain": "evil.example.com", "query_type": "A"},
                    headers=_h(token))
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["local_blacklist"]["matched"] is True
    assert d["local_blacklist"]["rule"] == "evil.example.com"
    assert d["domain_verdict"]["action"] == "intercept"
    assert d["final_verdict"]["action"] == "intercept"


def test_domain_wildcard_blacklist_hit(client, token):
    _add_list(client, token, "blacklist", "domain", "*.bad.com")
    r = client.post("/api/test/domain",
                    json={"domain": "a.b.bad.com", "query_type": "A"},
                    headers=_h(token))
    d = r.json()["data"]
    assert d["local_blacklist"]["matched"] is True
    assert d["local_blacklist"]["rule"] == "*.bad.com"


def test_whitelist_overrides_blacklist(client, token):
    _add_list(client, token, "blacklist", "domain", "dup.example.com")
    _add_list(client, token, "whitelist", "domain", "dup.example.com")
    r = client.post("/api/test/domain",
                    json={"domain": "dup.example.com", "query_type": "A"},
                    headers=_h(token))
    d = r.json()["data"]
    assert d["whitelist"]["matched"] is True
    assert d["domain_verdict"]["action"] == "allow"


def test_ip_cidr_blacklist_hit(client, token):
    _add_list(client, token, "blacklist", "ip", "93.184.216.0/24")
    r = client.post("/api/test/ip", json={"ip": "93.184.216.34"},
                    headers=_h(token))
    d = r.json()["data"]
    assert d["local_blacklist"]["matched"] is True
    assert d["local_blacklist"]["rule"] == "93.184.216.0/24"
    assert d["verdict"] == "intercept"


def test_ip_clean_when_no_rule(client, token):
    r = client.post("/api/test/ip", json={"ip": "1.2.3.4"},
                    headers=_h(token))
    d = r.json()["data"]
    assert d["local_blacklist"]["matched"] is False
    assert d["verdict"] == "allow"


# ---------------- 威胁情报逐源与融合 ----------------

def test_no_threatintel_sources_skip(client, token):
    """未启用任何情报源：跳过威胁情报检测（不是拦截）。"""
    r = client.post("/api/test/domain",
                    json={"domain": "normal.example.com", "query_type": "A"},
                    headers=_h(token))
    d = r.json()["data"]
    assert d["threatintel_domain"] == []
    assert d["domain_verdict"]["action"] == "forward"
    assert d["resolution"] is not None   # 继续走公网解析


def test_failsafe_intercept_when_all_sources_no_verdict(client, token):
    """启用 example 适配器（恒无结论）：全部源无结论 → 默认拦截。"""
    r = client.post("/api/threatintel",
                    json={"name": "example", "base_url": "",
                          "api_key": "", "enabled": True, "timeout_ms": 500},
                    headers=_h(token))
    assert r.status_code == 200
    r = client.post("/api/test/domain",
                    json={"domain": "normal.example.com", "query_type": "A"},
                    headers=_h(token))
    d = r.json()["data"]
    assert len(d["threatintel_domain"]) == 1
    assert d["threatintel_domain"][0]["status"] == "error"
    assert d["domain_verdict"]["action"] == "intercept"
    assert "fail-safe" in d["domain_verdict"]["reason"]


def test_ip_probe_per_source_detail(client, token):
    r = client.post("/api/threatintel",
                    json={"name": "example", "base_url": "",
                          "api_key": "", "enabled": True, "timeout_ms": 500},
                    headers=_h(token))
    r = client.post("/api/test/ip", json={"ip": "8.8.8.8"},
                    headers=_h(token))
    d = r.json()["data"]
    assert len(d["threatintel_ip"]) == 1
    assert d["threatintel_ip"][0]["source"] == "example"
    assert d["threatintel_ip"][0]["status"] in ("error", "hit", "miss")


def test_domain_test_validates_input(client, token):
    r = client.post("/api/test/domain", json={"domain": "", "query_type": "A"},
                    headers=_h(token))
    assert r.status_code == 400
    r = client.post("/api/test/domain",
                    json={"domain": "x.com", "query_type": "TXT"},
                    headers=_h(token))
    assert r.status_code == 400
    r = client.post("/api/test/ip", json={"ip": ""}, headers=_h(token))
    assert r.status_code == 400
