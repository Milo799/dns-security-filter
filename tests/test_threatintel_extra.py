"""新增内置情报源适配器测试（PhishTank / DShield / Blocklist.de / URLhaus）。

覆盖三态语义：命中 / 明确未命中 / 网络失败或结构异常 → None（无结论，
参与 fail-safe 默认拦截）；以及能力声明（域名 vs IP 支持范围）。
URLhaus 额外覆盖：官方现已强制要求 Auth-Key（HTTP 头），未配置 Key 时
应短路返回并给出可诊断的 last_error。
"""

from datetime import date, timedelta

import httpx

from app import http_client  # noqa: E402
import pytest

from adapters.phishtank import PhishTankAdapter
from adapters.dshield import DShieldAdapter
from adapters.blocklistde import BlocklistDeAdapter
from adapters.urlhaus import UrlhausAdapter


class FakeResp:
    def __init__(self, status_code=200, text="", payload=None, exc=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload
        self._exc = exc

    def json(self):
        if self._exc:
            raise self._exc
        if self._payload is None:
            raise ValueError("no json payload")
        return self._payload


# ================= PhishTank =================

def test_phishtank_hit(monkeypatch):
    a = PhishTankAdapter()
    monkeypatch.setattr(http_client, "post", lambda *a_, **k:
        FakeResp(payload={"results": {"in_database": True,
                                      "phish_id": 11728}}))
    r = a.query_domain("paypal.com.evil.example")
    assert r is not None and r.is_malicious
    assert "11728" in r.detail


def test_phishtank_miss(monkeypatch):
    a = PhishTankAdapter()
    monkeypatch.setattr(http_client, "post", lambda *a_, **k:
        FakeResp(payload={"results": {"in_database": False}}))
    r = a.query_domain("example.com")
    assert r is not None and not r.is_malicious


def test_phishtank_rate_limit_is_none(monkeypatch):
    a = PhishTankAdapter()
    monkeypatch.setattr(http_client, "post", lambda *a_, **k: FakeResp(509))
    assert a.query_domain("example.com") is None


def test_phishtank_bad_json_is_none(monkeypatch):
    a = PhishTankAdapter()
    monkeypatch.setattr(http_client, "post", lambda *a_, **k:
        FakeResp(text="<html>error</html>"))
    assert a.query_domain("example.com") is None


def test_phishtank_network_error_is_none(monkeypatch):
    a = PhishTankAdapter()
    def boom(*a_, **k):
        raise httpx.ConnectError("no network")
    monkeypatch.setattr(http_client, "post", boom)
    assert a.query_domain("example.com") is None


def test_phishtank_supports_ip_false():
    assert PhishTankAdapter().supports_ip is False
    assert PhishTankAdapter().supports_domain is True


# ================= DShield =================

def test_dshield_hit_active(monkeypatch):
    a = DShieldAdapter()
    today = date.today().isoformat()
    monkeypatch.setattr(http_client, "get", lambda *a_, **k:
        FakeResp(payload={"ip": {"number": "1.2.3.4", "count": "5000",
                                 "attacks": "34", "maxdate": today}}))
    r = a.query_ip("1.2.3.4")
    assert r is not None and r.is_malicious
    assert "5000" in r.detail


def test_dshield_below_min_count_is_miss(monkeypatch):
    a = DShieldAdapter()
    today = date.today().isoformat()
    monkeypatch.setattr(http_client, "get", lambda *a_, **k:
        FakeResp(payload={"ip": {"count": "50", "maxdate": today}}))
    r = a.query_ip("1.2.3.4")
    assert r is not None and not r.is_malicious


def test_dshield_stale_report_is_miss(monkeypatch):
    a = DShieldAdapter()
    old = (date.today() - timedelta(days=90)).isoformat()
    monkeypatch.setattr(http_client, "get", lambda *a_, **k:
        FakeResp(payload={"ip": {"count": "5000", "maxdate": old}}))
    r = a.query_ip("1.2.3.4")
    assert r is not None and not r.is_malicious


def test_dshield_no_record_is_miss(monkeypatch):
    a = DShieldAdapter()
    monkeypatch.setattr(http_client, "get", lambda *a_, **k:
        FakeResp(payload={"ip": {"number": "8.8.8.8"}}))
    r = a.query_ip("8.8.8.8")
    assert r is not None and not r.is_malicious


def test_dshield_rate_limit_is_none(monkeypatch):
    a = DShieldAdapter()
    monkeypatch.setattr(http_client, "get", lambda *a_, **k: FakeResp(429))
    assert a.query_ip("1.2.3.4") is None


def test_dshield_network_error_is_none(monkeypatch):
    a = DShieldAdapter()
    def boom(*a_, **k):
        raise httpx.ConnectError("no network")
    monkeypatch.setattr(http_client, "get", boom)
    assert a.query_ip("1.2.3.4") is None


def test_dshield_supports_domain_false():
    assert DShieldAdapter().supports_domain is False
    assert DShieldAdapter().supports_ip is True


def test_dshield_config_thresholds():
    import json
    a = DShieldAdapter(config=json.dumps({"min_count": 10, "max_age_days": 30}))
    assert a.min_count == 10 and a.max_age_days == 30


# ================= Blocklist.de =================

def test_blocklistde_hit(monkeypatch):
    a = BlocklistDeAdapter()
    monkeypatch.setattr(http_client, "get", lambda *a_, **k:
        FakeResp(text="attacks: 5<br />reports: 3<br />"
                      "lastreport: 2026-08-20 10:00:00<br />"))
    r = a.query_ip("1.2.3.4")
    assert r is not None and r.is_malicious
    assert "5" in r.detail


def test_blocklistde_miss(monkeypatch):
    a = BlocklistDeAdapter()
    monkeypatch.setattr(http_client, "get", lambda *a_, **k:
        FakeResp(text="attacks: 0<br />reports: 0<br />"))
    r = a.query_ip("8.8.8.8")
    assert r is not None and not r.is_malicious


def test_blocklistde_unparseable_is_none(monkeypatch):
    a = BlocklistDeAdapter()
    monkeypatch.setattr(http_client, "get", lambda *a_, **k:
        FakeResp(text="<html>maintenance</html>"))
    assert a.query_ip("1.2.3.4") is None


def test_blocklistde_network_error_is_none(monkeypatch):
    a = BlocklistDeAdapter()
    def boom(*a_, **k):
        raise httpx.TimeoutException("timeout")
    monkeypatch.setattr(http_client, "get", boom)
    assert a.query_ip("1.2.3.4") is None


def test_blocklistde_supports_domain_false():
    assert BlocklistDeAdapter().supports_domain is False
    assert BlocklistDeAdapter().supports_ip is True


# ================= URLhaus（需 Auth-Key） =================

def test_urlhaus_without_key_short_circuits():
    """未配置 Auth-Key 时短路返回 None，并给出可诊断的 last_error。"""
    a = UrlhausAdapter()
    assert a.query_domain("example.com") is None
    assert "Auth-Key" in a.last_error and "auth.abuse.ch" in a.last_error


def test_urlhaus_sends_auth_key_header(monkeypatch):
    a = UrlhausAdapter(api_key="my-key-1234")
    seen = {}

    def fake_post(url, data=None, headers=None, **k):
        seen["url"] = url
        seen["headers"] = headers or {}
        return FakeResp(payload={"query_status": "no_results", "urls": []})

    monkeypatch.setattr(http_client, "post", fake_post)
    r = a.query_domain("example.com")
    assert r is not None and not r.is_malicious
    assert seen["headers"].get("Auth-Key") == "my-key-1234"
    assert seen["url"].endswith("/v1/host/")
    assert a.last_error == ""


def test_urlhaus_hit(monkeypatch):
    a = UrlhausAdapter(api_key="k")
    monkeypatch.setattr(http_client, "post", lambda *a_, **k:
        FakeResp(payload={"query_status": "ok",
                          "urls": [{"url_id": 1, "url_status": "online"},
                                   {"url_id": 2, "url_status": "online"}]}))
    r = a.query_domain("evil.example.com")
    assert r is not None and r.is_malicious
    assert "2" in r.detail


def test_urlhaus_only_offline_is_miss(monkeypatch):
    """全部记录已离线（如 baidu.com 的 2021 死链）→ 明确未命中，不误拦。"""
    a = UrlhausAdapter(api_key="k")
    monkeypatch.setattr(http_client, "post", lambda *a_, **k:
        FakeResp(payload={"query_status": "ok",
                          "urls": [{"url_id": 1, "url_status": "offline"},
                                   {"url_id": 2, "url_status": "unknown"}]}))
    r = a.query_domain("www.baidu.com")
    assert r is not None and not r.is_malicious
    assert "历史记录" in r.detail


def test_urlhaus_mixed_online_offline_is_hit(monkeypatch):
    """只要存在当前在线恶意 URL 即命中（离线历史不影响判定）。"""
    a = UrlhausAdapter(api_key="k")
    monkeypatch.setattr(http_client, "post", lambda *a_, **k:
        FakeResp(payload={"query_status": "ok",
                          "urls": [{"url_id": 1, "url_status": "offline"},
                                   {"url_id": 2, "url_status": "online"}]}))
    r = a.query_domain("evil.example.com")
    assert r is not None and r.is_malicious
    assert "1 条当前在线" in r.detail


def test_urlhaus_miss(monkeypatch):
    a = UrlhausAdapter(api_key="k")
    monkeypatch.setattr(http_client, "post", lambda *a_, **k:
        FakeResp(payload={"query_status": "no_results", "urls": []}))
    r = a.query_domain("example.com")
    assert r is not None and not r.is_malicious


def test_urlhaus_unauthorized_is_none(monkeypatch):
    """Key 无效 → 401 → 无结论，并明确提示检查 Key。"""
    a = UrlhausAdapter(api_key="bad-key")
    monkeypatch.setattr(http_client, "post", lambda *a_, **k: FakeResp(401))
    assert a.query_domain("example.com") is None
    assert "Auth-Key" in a.last_error


def test_urlhaus_rate_limit_is_none(monkeypatch):
    a = UrlhausAdapter(api_key="k")
    monkeypatch.setattr(http_client, "post", lambda *a_, **k: FakeResp(429))
    assert a.query_domain("example.com") is None
    assert "rate limit" in a.last_error or "频繁" in a.last_error


def test_urlhaus_network_error_is_none(monkeypatch):
    a = UrlhausAdapter(api_key="k")
    def boom(*a_, **k):
        raise httpx.ConnectError("no network")
    monkeypatch.setattr(http_client, "post", boom)
    assert a.query_domain("example.com") is None
    assert "网络" in a.last_error


def test_urlhaus_bad_status_is_none(monkeypatch):
    """query_status 为 invalid_host 等 → 请求未成功，无结论。"""
    a = UrlhausAdapter(api_key="k")
    monkeypatch.setattr(http_client, "post", lambda *a_, **k:
        FakeResp(payload={"query_status": "invalid_host"}))
    assert a.query_domain("example.com") is None
    assert "invalid_host" in a.last_error


def test_urlhaus_ip_uses_host_endpoint(monkeypatch):
    """IP 查询也走 /v1/host/（官方无 /v1/ip/ 端点）。"""
    a = UrlhausAdapter(api_key="k")
    seen = {}

    def fake_post(url, data=None, headers=None, **k):
        seen["url"] = url
        seen["data"] = data
        return FakeResp(payload={"query_status": "no_results", "urls": []})

    monkeypatch.setattr(http_client, "post", fake_post)
    r = a.query_ip("8.8.8.8")
    assert r is not None and not r.is_malicious
    assert seen["url"].endswith("/v1/host/")
    assert seen["data"] == {"host": "8.8.8.8"}
