"""DNSBL 适配器单元测试（mock 查询，不依赖公网）。

覆盖：命中/未命中/无结论三态、IPv4 反查、IPv6 与非法 IP 处理、
能力声明、config 覆盖 zone、返回码含义。
"""

import pytest

from adapters.dnsbl import (
    SpamhausZenAdapter, SpamhausDBLAdapter, DroneBLAdapter, SPFBLAdapter,
)


def make(adapter_cls, lookup_result="SENTINEL", **kw):
    """构造适配器并把 _lookup 替换为假实现。

    lookup_result: "SENTINEL" 表示用真实 _lookup（测试里避免），
    其它值直接作为返回值（list 或 None）。
    """
    a = adapter_cls(**kw)
    if lookup_result != "SENTINEL":
        a._lookup = lambda fqdn: lookup_result
    return a


# ---------------- IPv4 反查 ----------------

def test_reverse_ipv4():
    a = make(SpamhausZenAdapter)
    assert a._reverse_ipv4("1.2.3.4") == "4.3.2.1"
    assert a._reverse_ipv4("8.8.8.8") == "8.8.8.8"
    assert a._reverse_ipv4("256.1.1.1") is None
    assert a._reverse_ipv4("1.2.3") is None
    assert a._reverse_ipv4("fe80::1") is None
    assert a._reverse_ipv4("abc") is None


# ---------------- 三态判定 ----------------

def test_hit_returns_malicious():
    a = make(SpamhausZenAdapter, lookup_result=["127.0.0.2"])
    r = a.query_ip("1.2.3.4")
    assert r is not None and r.is_malicious is True
    assert "SBL" in r.detail          # 返回码含义注入 detail
    assert "127.0.0.2" in r.detail


def test_miss_returns_clean():
    a = make(SpamhausZenAdapter, lookup_result=[])
    r = a.query_ip("1.2.3.4")
    assert r is not None and r.is_malicious is False


def test_no_verdict_on_network_failure():
    # 网络失败（_lookup 返回 None）→ 无结论，参与 fail-safe 默认拦截
    a = make(SpamhausZenAdapter, lookup_result=None)
    r = a.query_ip("1.2.3.4")
    assert r is None


def test_non_127_listing_is_clean():
    # DNSBL 应答理论上只返回 127.0.0.0/8；出现其它 A 记录视为未命中
    a = make(SpamhausZenAdapter, lookup_result=["8.8.8.8"])
    r = a.query_ip("1.2.3.4")
    assert r is not None and r.is_malicious is False


# ---------------- IP 输入边界 ----------------

def test_ipv6_not_supported_clean():
    # IPv6 反查机制不适用 → 明确未命中（不能返回 None 触发 fail-safe 误杀）
    a = make(SpamhausZenAdapter)
    r = a.query_ip("2001:4860:4860::8888")
    assert r is not None and r.is_malicious is False
    assert "IPv4" in r.detail


def test_invalid_ip_clean():
    a = make(SpamhausZenAdapter)
    r = a.query_ip("not-an-ip")
    assert r is not None and r.is_malicious is False


# ---------------- 能力声明与查询类型 ----------------

def test_zen_supports_ip_only():
    a = make(SpamhausZenAdapter)
    assert a.supports_ip is True
    assert a.supports_domain is False
    r = a.query_domain("example.com")
    assert r is not None and r.is_malicious is False
    assert "不支持域名查询" in r.detail


def test_dbl_supports_domain_only():
    a = make(SpamhausDBLAdapter)
    assert a.supports_domain is True
    assert a.supports_ip is False
    r = a.query_ip("1.2.3.4")
    assert r is not None and r.is_malicious is False
    assert "不支持 IP 查询" in r.detail


def test_spfbl_supports_both():
    a = make(SPFBLAdapter, lookup_result=["127.0.0.2"])
    assert a.supports_domain and a.supports_ip
    rd = a.query_domain("example.com")
    assert rd is not None and rd.is_malicious
    ri = a.query_ip("1.2.3.4")
    assert ri is not None and ri.is_malicious


# ---------------- 域名查询拼接 ----------------

def test_domain_query_uses_zone_suffix():
    a = make(SpamhausDBLAdapter, lookup_result=["127.0.1.5"])
    captured = {}
    a._lookup = lambda fqdn: captured.__setitem__("fqdn", fqdn) or ["127.0.1.5"]
    r = a.query_domain("example.com")
    assert captured["fqdn"] == "example.com.dbl.spamhaus.org"
    assert r.is_malicious and "恶意软件" in r.detail


# ---------------- config 覆盖 ----------------

def test_config_overrides_zone():
    a = make(SpamhausZenAdapter,
             config='{"zone": "my.custom.zone", "resolver": "1.1.1.1"}')
    assert a.zone == "my.custom.zone"
    assert a.resolver == "1.1.1.1"


def test_bad_config_ignored():
    a = make(SpamhausZenAdapter, config="not-json")
    assert a.zone == "zen.spamhaus.org"


# ---------------- 代码含义表 ----------------

@pytest.mark.parametrize("adapter_cls,code,expect", [
    (DroneBLAdapter, "127.0.0.3", "暴力"),
    (DroneBLAdapter, "127.0.0.4", "恶意软件"),
    (SpamhausDBLAdapter, "127.0.1.4", "钓鱼"),
    (SpamhausDBLAdapter, "127.0.1.106", "僵尸"),
    (SpamhausZenAdapter, "127.0.0.10", "PBL"),
])
def test_code_meaning(adapter_cls, code, expect):
    a = make(adapter_cls, lookup_result=[code])
    r = a.query_ip("1.2.3.4") if a.supports_ip else a.query_domain("example.com")
    assert r is not None and r.is_malicious
    assert expect in r.detail


def test_unknown_code_still_malicious():
    a = make(SpamhausZenAdapter, lookup_result=["127.0.0.99"])
    r = a.query_ip("1.2.3.4")
    assert r is not None and r.is_malicious is True


# ---------------- 公共解析器限流/拒答码（127.255.255.25x） ----------------

def test_rate_limited_254_no_verdict():
    # Spamhaus 公共解析器限流码 127.255.255.254 → 无结论（fail-safe），
    # 绝不能当成命中（否则公共 DNS 大流量查询会大面积误拦）
    a = make(SpamhausZenAdapter, lookup_result=["127.255.255.254"])
    r = a.query_ip("1.2.3.4")
    assert r is None


def test_rate_limited_252_no_verdict():
    # Spamhaus 拒答码 127.255.255.252（策略拒绝）→ 同样无结论
    a = make(SpamhausDBLAdapter, lookup_result=["127.255.255.252"])
    r = a.query_domain("example.com")
    assert r is None


def test_rate_limited_mixed_with_hit():
    # 限流码与真实命中并存时，只认真实命中（限流码不参与判定，也不掩盖命中）
    a = make(SPFBLAdapter, lookup_result=["127.255.255.254", "127.0.0.2"])
    r = a.query_ip("1.2.3.4")
    assert r is not None and r.is_malicious is True


def test_rate_limited_mixed_with_miss():
    # 限流码 + 非命中记录（如 zone 自身 A 记录泄漏）→ 无结论
    a = make(SPFBLAdapter, lookup_result=["127.255.255.254", "54.233.253.229"])
    r = a.query_ip("1.2.3.4")
    assert r is None
