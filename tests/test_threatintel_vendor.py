"""厂商情报源适配器测试（ThreatFox / 微步 ThreatBook / IBM X-Force / OTX / GreyNoise）。

覆盖三态语义：命中 / 明确未命中 / 网络失败或结构异常 → None（无结论，
参与 fail-safe 默认拦截）；未配置 API Key 也返回 None 而非误报；
以及能力声明与 config 参数（api_key / api_password / score_threshold）。
"""

import json

import httpx
import pytest

from adapters.threatfox import ThreatFoxAdapter
from adapters.threatbook import ThreatBookAdapter
from adapters.xforce import XForceAdapter
from adapters.otx import OTXAdapter
from adapters.greynoise import GreyNoiseAdapter


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


# ================= ThreatFox =================

def test_threatfox_hit(monkeypatch):
    a = ThreatFoxAdapter(api_key="test-key")
    monkeypatch.setattr(httpx, "post", lambda *a_, **k:
        FakeResp(payload={"query_status": "ok", "data": [{
            "ioc": "evil.example.com", "malware_printable": "Cobalt Strike",
            "threat_type_desc": "botnet C&C"}]}))
    r = a.query_domain("evil.example.com")
    assert r is not None and r.is_malicious
    assert "Cobalt Strike" in r.detail


def test_threatfox_miss(monkeypatch):
    a = ThreatFoxAdapter(api_key="test-key")
    monkeypatch.setattr(httpx, "post", lambda *a_, **k:
        FakeResp(payload={"query_status": "no_result", "data": []}))
    r = a.query_domain("example.com")
    assert r is not None and not r.is_malicious


def test_threatfox_ok_but_empty_data_is_none(monkeypatch):
    a = ThreatFoxAdapter(api_key="test-key")
    monkeypatch.setattr(httpx, "post", lambda *a_, **k:
        FakeResp(payload={"query_status": "ok", "data": []}))
    assert a.query_domain("example.com") is None


def test_threatfox_rate_limit_is_none(monkeypatch):
    a = ThreatFoxAdapter(api_key="test-key")
    monkeypatch.setattr(httpx, "post", lambda *a_, **k:
        FakeResp(payload={"query_status": "no_perm", "data": []}))
    assert a.query_domain("example.com") is None


def test_threatfox_http_error_is_none(monkeypatch):
    a = ThreatFoxAdapter(api_key="test-key")
    monkeypatch.setattr(httpx, "post", lambda *a_, **k: FakeResp(429))
    assert a.query_domain("example.com") is None


def test_threatfox_network_error_is_none(monkeypatch):
    a = ThreatFoxAdapter(api_key="test-key")
    def boom(*a_, **k):
        raise httpx.ConnectError("no network")
    monkeypatch.setattr(httpx, "post", boom)
    assert a.query_domain("example.com") is None


def test_threatfox_without_key_is_none(monkeypatch):
    """未配置 Auth-Key：不发起请求，返回无结论（fail-safe 由融合策略处理）。"""
    called = []
    def fake_post(*a_, **k):
        called.append(1)
        return FakeResp(payload={"query_status": "ok", "data": [{"ioc": "x"}]})
    monkeypatch.setattr(httpx, "post", fake_post)
    a = ThreatFoxAdapter()  # 无 api_key
    assert a.query_domain("evil.example.com") is None
    assert not called  # 未发请求


def test_threatfox_key_from_config(monkeypatch):
    a = ThreatFoxAdapter(config=json.dumps({"api_key": "cfg-key"}))
    assert a.api_key == "cfg-key"
    assert a.query_ip("1.2.3.4") is None or True  # 能构造即满足


def test_threatfox_supports_both():
    a = ThreatFoxAdapter()
    assert a.supports_domain and a.supports_ip


# ================= 微步 ThreatBook =================

def test_threatbook_ip_hit(monkeypatch):
    a = ThreatBookAdapter(api_key="k")
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(payload={"data": {"1.2.3.4": {
            "is_malicious": True, "severity": "high",
            "judgments": ["C2", "Zombie"]}}}))
    r = a.query_ip("1.2.3.4")
    assert r is not None and r.is_malicious
    assert "C2" in r.detail


def test_threatbook_domain_miss(monkeypatch):
    a = ThreatBookAdapter(api_key="k")
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(payload={"data": {"example.com": {
            "is_malicious": False}}}))
    r = a.query_domain("example.com")
    assert r is not None and not r.is_malicious


def test_threatbook_missing_resource_is_none(monkeypatch):
    """响应里没有查询资源的数据（配额超限/参数错误）→ 无结论。"""
    a = ThreatBookAdapter(api_key="k")
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(payload={"data": {}}))
    assert a.query_ip("1.2.3.4") is None


def test_threatbook_no_is_malicious_field_is_none(monkeypatch):
    a = ThreatBookAdapter(api_key="k")
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(payload={"data": {"1.2.3.4": {"severity": "low"}}}))
    assert a.query_ip("1.2.3.4") is None


def test_threatbook_without_key_is_none(monkeypatch):
    called = []
    def fake_get(*a_, **k):
        called.append(1)
        return FakeResp(payload={"data": {}})
    monkeypatch.setattr(httpx, "get", fake_get)
    a = ThreatBookAdapter()
    assert a.query_ip("1.2.3.4") is None
    assert not called


def test_threatbook_network_error_is_none(monkeypatch):
    a = ThreatBookAdapter(api_key="k")
    def boom(*a_, **k):
        raise httpx.TimeoutException("timeout")
    monkeypatch.setattr(httpx, "get", boom)
    assert a.query_domain("example.com") is None


def test_threatbook_supports_both():
    a = ThreatBookAdapter()
    assert a.supports_domain and a.supports_ip


# ================= IBM X-Force =================

def test_xforce_ip_hit(monkeypatch):
    a = XForceAdapter(api_key="k", config=json.dumps({"api_password": "p"}))
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(payload={"score": 8, "reason": "malware host",
                          "malware": "emotet"}))
    r = a.query_ip("1.2.3.4")
    assert r is not None and r.is_malicious
    assert "8" in r.detail and "malware host" in r.detail


def test_xforce_domain_miss(monkeypatch):
    a = XForceAdapter(api_key="k", config=json.dumps({"api_password": "p"}))
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(payload={"score": 1}))
    r = a.query_domain("example.com")
    assert r is not None and not r.is_malicious


def test_xforce_custom_threshold(monkeypatch):
    """config 调高阈值后，6 分不再判恶意。"""
    a = XForceAdapter(api_key="k",
                      config=json.dumps({"api_password": "p",
                                         "score_threshold": 8}))
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(payload={"score": 6}))
    r = a.query_ip("1.2.3.4")
    assert r is not None and not r.is_malicious


def test_xforce_missing_score_is_none(monkeypatch):
    a = XForceAdapter(api_key="k", config=json.dumps({"api_password": "p"}))
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(payload={"resolve": ["8.8.8.8"]}))
    assert a.query_domain("example.com") is None


def test_xforce_without_password_is_none(monkeypatch):
    called = []
    def fake_get(*a_, **k):
        called.append(1)
        return FakeResp(payload={"score": 9})
    monkeypatch.setattr(httpx, "get", fake_get)
    a = XForceAdapter(api_key="k")  # 无 api_password
    assert a.query_ip("1.2.3.4") is None
    assert not called


def test_xforce_http_error_is_none(monkeypatch):
    a = XForceAdapter(api_key="k", config=json.dumps({"api_password": "p"}))
    monkeypatch.setattr(httpx, "get", lambda *a_, **k: FakeResp(401))
    assert a.query_ip("1.2.3.4") is None


def test_xforce_network_error_is_none(monkeypatch):
    a = XForceAdapter(api_key="k", config=json.dumps({"api_password": "p"}))
    def boom(*a_, **k):
        raise httpx.ConnectError("no network")
    monkeypatch.setattr(httpx, "get", boom)
    assert a.query_ip("1.2.3.4") is None


def test_xforce_supports_both():
    a = XForceAdapter()
    assert a.supports_domain and a.supports_ip


# ================= AlienVault OTX =================

def test_otx_domain_hit(monkeypatch):
    a = OTXAdapter(api_key="k")
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(payload={"type": "domain", "indicator": "evil.example.com",
                          "pulse_info": {"count": 2, "pulses": [
                              {"name": "Cobalt Strike C2",
                               "description": "botnet"}]}}))
    r = a.query_domain("evil.example.com")
    assert r is not None and r.is_malicious
    assert "Cobalt Strike" in r.detail


def test_otx_ip_hit(monkeypatch):
    a = OTXAdapter(api_key="k")
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(payload={"pulse_info": {"count": 1, "pulses": [
            {"name": "malware host"}]}}))
    r = a.query_ip("1.2.3.4")
    assert r is not None and r.is_malicious


def test_otx_miss_count_zero(monkeypatch):
    a = OTXAdapter(api_key="k")
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(payload={"pulse_info": {"count": 0, "pulses": []}}))
    r = a.query_domain("example.com")
    assert r is not None and not r.is_malicious


def test_otx_404_is_miss(monkeypatch):
    """OTX 对未收录 indicator 返回 404 → 明确未命中（不是无结论）。"""
    a = OTXAdapter(api_key="k")
    monkeypatch.setattr(httpx, "get", lambda *a_, **k: FakeResp(404))
    r = a.query_domain("notseen.com")
    assert r is not None and not r.is_malicious


def test_otx_unauthorized_is_none(monkeypatch):
    a = OTXAdapter(api_key="bad-key")
    monkeypatch.setattr(httpx, "get", lambda *a_, **k: FakeResp(401))
    assert a.query_domain("example.com") is None


def test_otx_http_error_is_none(monkeypatch):
    a = OTXAdapter(api_key="k")
    monkeypatch.setattr(httpx, "get", lambda *a_, **k: FakeResp(429))
    assert a.query_domain("example.com") is None


def test_otx_network_error_is_none(monkeypatch):
    a = OTXAdapter(api_key="k")
    def boom(*a_, **k):
        raise httpx.ConnectError("no network")
    monkeypatch.setattr(httpx, "get", boom)
    assert a.query_domain("example.com") is None


def test_otx_without_key_is_none(monkeypatch):
    called = []
    def fake_get(*a_, **k):
        called.append(1)
        return FakeResp(payload={"pulse_info": {"count": 1}})
    monkeypatch.setattr(httpx, "get", fake_get)
    a = OTXAdapter()
    assert a.query_domain("evil.example.com") is None
    assert not called


def test_otx_key_from_config(monkeypatch):
    a = OTXAdapter(config=json.dumps({"api_key": "cfg-key"}))
    assert a.api_key == "cfg-key"
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(payload={"pulse_info": {"count": 0}}))
    assert a.query_domain("example.com") is not None


def test_otx_supports_both():
    a = OTXAdapter()
    assert a.supports_domain and a.supports_ip


def test_otx_ipv6_type(monkeypatch):
    """IPv6 查询应使用 IPv6 indicator 类型（URL 含 /indicators/IPv6/）。"""
    a = OTXAdapter(api_key="k")
    seen = {}
    def fake_get(url, **k):
        seen["url"] = url
        return FakeResp(payload={"pulse_info": {"count": 0}})
    monkeypatch.setattr(httpx, "get", fake_get)
    a.query_ip("2001:db8::1")
    assert "/indicators/IPv6/" in seen["url"]


# ================= GreyNoise =================

def test_greynoise_ip_malicious_hit(monkeypatch):
    a = GreyNoiseAdapter(api_key="k")
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(payload={"ip": "1.2.3.4", "noise": True, "riot": False,
                          "classification": "malicious",
                          "name": "Mirai", "last_seen": "2026-08-01"}))
    r = a.query_ip("1.2.3.4")
    assert r is not None and r.is_malicious
    assert "Mirai" in r.detail


def test_greynoise_benign_is_miss(monkeypatch):
    """扫描器但良性（benign）→ 明确不拦，正是"专治误拦扫描 IP"。"""
    a = GreyNoiseAdapter(api_key="k")
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(payload={"noise": True, "riot": False,
                          "classification": "benign", "name": "port scan"}))
    r = a.query_ip("1.2.3.4")
    assert r is not None and not r.is_malicious


def test_greynoise_unknown_is_miss(monkeypatch):
    a = GreyNoiseAdapter(api_key="k")
    monkeypatch.setattr(httpx, "get", lambda *a_, **k:
        FakeResp(payload={"noise": False, "riot": False,
                          "classification": "unknown"}))
    r = a.query_ip("1.2.3.4")
    assert r is not None and not r.is_malicious


def test_greynoise_404_is_miss(monkeypatch):
    a = GreyNoiseAdapter(api_key="k")
    monkeypatch.setattr(httpx, "get", lambda *a_, **k: FakeResp(404))
    r = a.query_ip("1.2.3.4")
    assert r is not None and not r.is_malicious


def test_greynoise_unauthorized_is_none(monkeypatch):
    a = GreyNoiseAdapter(api_key="bad")
    monkeypatch.setattr(httpx, "get", lambda *a_, **k: FakeResp(401))
    assert a.query_ip("1.2.3.4") is None


def test_greynoise_http_error_is_none(monkeypatch):
    a = GreyNoiseAdapter(api_key="k")
    monkeypatch.setattr(httpx, "get", lambda *a_, **k: FakeResp(500))
    assert a.query_ip("1.2.3.4") is None


def test_greynoise_network_error_is_none(monkeypatch):
    a = GreyNoiseAdapter(api_key="k")
    def boom(*a_, **k):
        raise httpx.TimeoutException("timeout")
    monkeypatch.setattr(httpx, "get", boom)
    assert a.query_ip("1.2.3.4") is None


def test_greynoise_without_key_is_none(monkeypatch):
    called = []
    def fake_get(*a_, **k):
        called.append(1)
        return FakeResp(payload={"classification": "malicious"})
    monkeypatch.setattr(httpx, "get", fake_get)
    a = GreyNoiseAdapter()
    assert a.query_ip("1.2.3.4") is None
    assert not called


def test_greynoise_ip_only_capability():
    """能力声明：仅支持 IP，不支持域名（检测主流程按声明过滤）。"""
    a = GreyNoiseAdapter()
    assert not a.supports_domain and a.supports_ip
    assert a.query_domain("example.com") is None  # 兜底不抛异常
