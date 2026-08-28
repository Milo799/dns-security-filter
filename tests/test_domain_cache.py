"""域名检测结论缓存（LRU + TTL）测试—— 10 万终端前置开发项 1。

覆盖：
  - 基本命中/未命中（键规范化：大小写、尾点）
  - TTL 过期（惰性删除）
  - LRU 淘汰（容量上限，最旧先淘汰；触碰续命）
  - fail-safe 结论不写缓存（query_threatintel_domain 全源无结论路径）
  - 情报源配置变更 → threatintel_invalidate() 全清
  - 命中缓存跳过在线查询（mock 适配器计数）
  - 配置热调（TTL/容量运行时改 CONFIG 立即生效）
"""

import threading
import time

import pytest
from dnslib import DNSRecord

import domain_cache
from config import CONFIG
from detectors import process_query, query_threatintel_domain
from app.db import db_cursor


@pytest.fixture(autouse=True)
def clean_cache():
    """每个测试前后清空缓存并复位统计。"""
    domain_cache.clear()
    domain_cache.STATS["hits"] = 0
    domain_cache.STATS["misses"] = 0
    yield
    domain_cache.clear()
    domain_cache.STATS["hits"] = 0
    domain_cache.STATS["misses"] = 0


@pytest.fixture
def cache_config():
    """临时缓存配置（TTL=60s，容量默认），测试后还原。"""
    old_ttl, old_size = CONFIG.domain_cache_ttl_s, CONFIG.domain_cache_size
    CONFIG.domain_cache_ttl_s = 60
    yield CONFIG
    CONFIG.domain_cache_ttl_s, CONFIG.domain_cache_size = old_ttl, old_size


# ---------------- 基础：命中 / 未命中 / 键规范化 ----------------

def test_cache_roundtrip(cache_config):
    domain_cache.put("Example.COM", True, "threatintel:any:test")
    assert domain_cache.get("example.com") == (True, "threatintel:any:test")
    assert domain_cache.get("example.com.") == (True, "threatintel:any:test")  # 尾点
    assert domain_cache.get("other.com") is None


def test_cache_miss_counts(cache_config):
    domain_cache.get("nope.com")
    domain_cache.get("nope.com")
    assert domain_cache.stats()["misses"] == 2
    assert domain_cache.stats()["hits"] == 0


# ---------------- TTL 过期 ----------------

def test_ttl_expiry(cache_config, monkeypatch):
    CONFIG.domain_cache_ttl_s = 1
    domain_cache.put("a.test", False, "threatintel:any:test")
    assert domain_cache.get("a.test") is not None      # 未过期
    # 快进时间：把已存条目的 expire_at 改到过去
    with domain_cache._LOCK:
        for k, v in domain_cache._CACHE.items():
            domain_cache._CACHE[k] = (v[0], v[1], time.monotonic() - 1)
    assert domain_cache.get("a.test") is None          # 已过期（惰性删除）


# ---------------- LRU 淘汰 ----------------

def test_lru_eviction(cache_config):
    CONFIG.domain_cache_size = 1024                    # 最小容量
    for i in range(1024):
        domain_cache.put(f"d{i}.test", False, "r")
    assert domain_cache.stats()["size"] == 1024        # 恰好满（用 size 断言，get 会触碰 LRU）
    domain_cache.put("new.test", False, "r")           # 超容 → 淘汰最旧 d0
    assert domain_cache.get("d0.test") is None
    assert domain_cache.get("d1.test") is not None


def test_lru_touch_reorders(cache_config):
    CONFIG.domain_cache_size = 1024
    for i in range(1024):
        domain_cache.put(f"d{i}.test", False, "r")
    domain_cache.get("d0.test")                        # 触碰 d0 → 不再是最旧
    domain_cache.put("new.test", False, "r")           # 淘汰的是 d1
    assert domain_cache.get("d0.test") is not None
    assert domain_cache.get("d1.test") is None


# ---------------- 失效联动 ----------------

def test_threatintel_invalidate_clears(cache_config):
    domain_cache.put("a.test", True, "r")
    domain_cache.put("b.test", False, "r")
    domain_cache.threatintel_invalidate()
    assert domain_cache.get("a.test") is None
    assert domain_cache.get("b.test") is None
    assert domain_cache.stats()["size"] == 0


# ---------------- query_threatintel_domain 集成 ----------------

def _insert_source(name: str, adapter_cls=None):
    """插入一个启用的情报源配置行（example 适配器，真实查询走网络前先 mock）。"""
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO threatintel_api
               (name, adapter_type, base_url, enabled, timeout_ms, config, description)
               VALUES (?, 'http', '', 1, 2000, '', 'test')""",
            (name,),
        )


def test_query_result_cached(cache_config, monkeypatch):
    """有结论的查询写缓存；第二次查询不再调适配器（计数验证）。"""
    import detectors as detectors_mod
    import adapters as adapters_mod
    from adapters import ThreatResult

    calls = {"n": 0}

    class FakeAdapter(adapters_mod.ThreatIntelAdapter):
        name = "example"
        supports_domain = True
        supports_ip = False

        def query_domain(self, domain):
            calls["n"] += 1
            return ThreatResult(is_malicious=False, source="example")

        def query_ip(self, ip):
            return None

    # detectors 持有 from-import 绑定，须 patch detectors 命名空间
    monkeypatch.setattr(detectors_mod, "get_enabled_adapters",
                        lambda: [FakeAdapter()])

    r1 = query_threatintel_domain("repeat.test")
    assert r1 == (False, "threatintel:any:example")
    assert calls["n"] == 1

    r2 = query_threatintel_domain("repeat.test")
    assert r2 == r1
    assert calls["n"] == 1                            # 累计计数不变=命中缓存零新调用

    # 大小写变体同样命中（键规范化）
    r3 = query_threatintel_domain("REPEAT.Test")
    assert r3 == r1
    assert calls["n"] == 1


def test_failsafe_not_cached(cache_config, monkeypatch):
    """全部源无结论（fail-safe 默认拦截）不写缓存——每次都重新检测。"""
    import detectors as detectors_mod
    import adapters as adapters_mod

    calls = {"n": 0}

    class DeadAdapter(adapters_mod.ThreatIntelAdapter):
        name = "example"
        supports_domain = True
        supports_ip = False

        def query_domain(self, domain):
            calls["n"] += 1
            return None                               # 无结论（超时/故障）

        def query_ip(self, ip):
            return None

    monkeypatch.setattr(detectors_mod, "get_enabled_adapters",
                        lambda: [DeadAdapter()])

    for _ in range(2):
        malicious, reason = query_threatintel_domain("dead.test")
        assert malicious is True                      # fail-safe 默认拦截
        assert reason.startswith("threatintel:")
    assert calls["n"] == 2                            # 两次都真实查询（未缓存）
    assert domain_cache.stats()["size"] == 0          # 无落缓存


def test_no_adapters_skips_cache(cache_config, monkeypatch):
    """无支持域名查询的源 → 跳过检测，也不写缓存。"""
    import detectors as detectors_mod
    monkeypatch.setattr(detectors_mod, "get_enabled_adapters", lambda: [])
    malicious, reason = query_threatintel_domain("skip.test")
    assert malicious is False and reason == ""
    assert domain_cache.stats()["size"] == 0


# ---------------- 线程安全（并发读写不崩） ----------------

def test_concurrent_access(cache_config):
    errors = []

    def worker(n):
        try:
            for i in range(200):
                domain_cache.put(f"w{n}-{i}.test", i % 2 == 0, "r")
                domain_cache.get(f"w{n}-{i}.test")
        except Exception as e:                        # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
