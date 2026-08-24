"""新增内置免 Key 情报源（PhishTank / DShield / Blocklist.de）适配器测试。

覆盖三态语义：命中 / 明确未命中 / 网络失败或结构异常 → None（无结论，
参与 fail-safe 默认拦截）；以及能力声明（域名 vs IP 支持范围）。
"""

from datetime import date, timedelta

import httpx
import pytest

from adapters.phishtank import PhishTankAdapter
from adapters.dshield import DShieldAdapter
from adapters.blocklistde import BlocklistDeAdapter


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
    monkeypatch.setattr(httpx, "post", lambda *a_, **k:
        FakeResp(payload={"results": {"in_database": True,
                                      "phish_id": 11728}}))
    r = a.query_domain("paypal.com.evil.example")
    assert r is not None and r.is_malicious
    assert "11728" in r.detail


def test_phishtank_miss(monkeypatch):
    a = PhishTankAdapter()
    monkeypatch.setattr(httpx, "post", lambda *a_, **k:
        FakeResp(payload={"results": {"in_database": False}}))
    r = a.query_domain("example.com")
    assert r is not None and not r.is_malicious


def test_phishtank_rate_limit_is_none(monkeypatch):
    a = PhishTankAdapter()
    monkeypatch.setattr(httpx, "post", lambda *a_, **k: FakeResp(509))
    assert a.query_domain("example.com") is None


def test_phishtank_bad_json_is_none(monkeypatch):
    a = PhishTankAdapter()
    monkeypatch.setattr(httpx, "post", lambda *a_, **k:
        FakeResp(text="<html>error</html>"))
    assert a.query_domain("example.com") is None


def test_phishtank_network_error_is_none(monkeypatch):
    a = PhishTankAdapter()
    def boom(*a_, **k):
        raise httpx.ConnectError("no network")
    monkeypatch.setattr(httpx, "post", boom)
    assert a.query_domain("example.com") is None


def test_phishtank_supports_ip_false():
    assert PhishTankAdapter().supports_ip is False
    assert PhishTankAdapter().supports_domain is True


# ================= DShield =================

def test_dshield_hit_active(monkeypatch):
    a = DShieldAdapter()
    today = date.today().isoformat()
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(payload={"ip": {"number": "1.2.3.4", "count": "5000",
                                 "attacks": "34", "maxdate": today}}))
    r = a.query_ip("1.2.3.4")
    assert r is not None and r.is_malicious
    assert "5000" in r.detail


def test_dshield_below_min_count_is_miss(monkeypatch):
    a = DShieldAdapter()
    today = date.today().isoformat()
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(payload={"ip": {"count": "50", "maxdate": today}}))
    r = a.query_ip("1.2.3.4")
    assert r is not None and not r.is_malicious


def test_dshield_stale_report_is_miss(monkeypatch):
    a = DShieldAdapter()
    old = (date.today() - timedelta(days=90)).isoformat()
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(payload={"ip": {"count": "5000", "maxdate": old}}))
    r = a.query_ip("1.2.3.4")
    assert r is not None and not r.is_malicious


def test_dshield_no_record_is_miss(monkeypatch):
    a = DShieldAdapter()
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(payload={"ip": {"number": "8.8.8.8"}}))
    r = a.query_ip("8.8.8.8")
    assert r is not None and not r.is_malicious


def test_dshield_rate_limit_is_none(monkeypatch):
    a = DShieldAdapter()
    monkeypatch.setattr(httpx, "get", lambda *a_, **k: FakeResp(429))
    assert a.query_ip("1.2.3.4") is None


def test_dshield_network_error_is_none(monkeypatch):
    a = DShieldAdapter()
    def boom(*a_, **k):
        raise httpx.ConnectError("no network")
    monkeypatch.setattr(httpx, "get", boom)
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
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(text="attacks: 5<br />reports: 3<br />"
                      "lastreport: 2026-08-20 10:00:00<br />"))
    r = a.query_ip("1.2.3.4")
    assert r is not None and r.is_malicious
    assert "5" in r.detail


def test_blocklistde_miss(monkeypatch):
    a = BlocklistDeAdapter()
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(text="attacks: 0<br />reports: 0<br />"))
    r = a.query_ip("8.8.8.8")
    assert r is not None and not r.is_malicious


def test_blocklistde_unparseable_is_none(monkeypatch):
    a = BlocklistDeAdapter()
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(text="<html>maintenance</html>"))
    assert a.query_ip("1.2.3.4") is None


def test_blocklistde_network_error_is_none(monkeypatch):
    a = BlocklistDeAdapter()
    def boom(*a_, **k):
        raise httpx.TimeoutException("timeout")
    monkeypatch.setattr(httpx, "get", boom)
    assert a.query_ip("1.2.3.4") is None


def test_blocklistde_supports_domain_false():
    assert BlocklistDeAdapter().supports_domain is False
    assert BlocklistDeAdapter().supports_ip is True
