"""解析速度优化项测试：IP 结论缓存 / IP 后置并行 / 单次上游往返 / 跨进程轮询。

对应 2026-08-31 评估后的改动：
  A1 ip_cache（TTL+LRU+失效联动） + query_threatintel_ip 接缓存
  A2 seed 默认启用 DNSBL 四源
  B3 ip_postfilter 多 IP 并行
  B4 主流程单次上游往返（全正常路径不再二次解析）
  C5 cross_sync 跨进程变更轮询
"""

import time
from unittest.mock import patch

import pytest
from dnslib import DNSRecord, QTYPE, RR, A, RCODE

import domain_cache
import ip_cache
import cross_sync
import detectors
from adapters import ThreatResult
from config import CONFIG


# ---------------------------------------------------------------------------
# A1: ip_cache 模块
# ---------------------------------------------------------------------------

class TestIpCacheModule:
    def setup_method(self):
        ip_cache.clear()

    def test_put_get_roundtrip(self):
        ip_cache.put("1.2.3.4", False, "threatintel:any:spamhaus_zen")
        assert ip_cache.get("1.2.3.4") == (False, "threatintel:any:spamhaus_zen")
        ip_cache.put("5.6.7.8", True, "threatintel:any:spamhaus_zen")
        assert ip_cache.get("5.6.7.8") == (True, "threatintel:any:spamhaus_zen")

    def test_miss_returns_none(self):
        assert ip_cache.get("10.0.0.1") is None

    def test_ttl_expiry(self):
        with patch.object(CONFIG, "ip_cache_ttl_s", 1):
            ip_cache.put("1.1.1.1", False, "r")
            time.sleep(1.1)
            assert ip_cache.get("1.1.1.1") is None

    def test_lru_eviction(self):
        with patch.object(CONFIG, "ip_cache_size", 1024):
            for i in range(1025):
                ip_cache.put(f"10.0.{i // 256}.{i % 256}", False, "r")
            assert len(ip_cache._CACHE) == 1024
            # 最早写入的已被淘汰
            assert ip_cache.get("10.0.0.0") is None
            assert ip_cache.get("10.0.4.0") == (False, "r")   # 第 1025 条仍在

    def test_invalidate_clears(self):
        ip_cache.put("1.2.3.4", False, "r")
        ip_cache.threatintel_invalidate()
        assert ip_cache.get("1.2.3.4") is None

    def test_stats(self):
        base = ip_cache.stats()
        ip_cache.get("x")                       # miss
        ip_cache.put("1.2.3.4", False, "r")
        ip_cache.get("1.2.3.4")                 # hit
        s = ip_cache.stats()
        assert s["hits"] - base["hits"] == 1
        assert s["misses"] - base["misses"] == 1


# ---------------------------------------------------------------------------
# A1: query_threatintel_ip 缓存接入（mock 适配器计数验证跳过在线查询）
# ---------------------------------------------------------------------------

class _FakeAdapter:
    """计数型假适配器：每次查询计数并返回明确未命中。"""
    name = "fake_dnsbl"
    supports_domain = False
    supports_ip = True

    def __init__(self):
        self.calls = 0

    def query_domain(self, domain):
        return None

    def query_ip(self, ip):
        self.calls += 1
        return ThreatResult(is_malicious=False, source=self.name)


class TestThreatintelIpCache:
    def setup_method(self):
        ip_cache.clear()
        self.fake = _FakeAdapter()

    def test_second_query_hits_cache(self):
        with patch.object(detectors, "get_enabled_adapters",
                          return_value=[self.fake]):
            r1 = detectors.query_threatintel_ip("8.8.8.8")
            r2 = detectors.query_threatintel_ip("8.8.8.8")
        assert r1 == r2 == (False, "threatintel:any:fake_dnsbl")
        assert self.fake.calls == 1          # 第二次走缓存，适配器只被调一次

    def test_failsafe_not_cached(self):
        class _DeadAdapter(_FakeAdapter):
            def query_ip(self, ip):
                self.calls += 1
                return None                  # 无结论 → fail-safe

        dead = _DeadAdapter()
        with patch.object(detectors, "get_enabled_adapters", return_value=[dead]):
            r1 = detectors.query_threatintel_ip("9.9.9.9")
            r2 = detectors.query_threatintel_ip("9.9.9.9")
        assert r1[0] is True                 # 默认拦截
        assert dead.calls == 2               # fail-safe 不缓存：两次都实查
        assert ip_cache.get("9.9.9.9") is None

    def test_no_adapters_skips(self):
        with patch.object(detectors, "get_enabled_adapters", return_value=[]):
            assert detectors.query_threatintel_ip("1.1.1.1") == (False, "")


# ---------------------------------------------------------------------------
# B3: ip_postfilter 并行与正确性
# ---------------------------------------------------------------------------

class TestIpPostfilter:
    def setup_method(self):
        ip_cache.clear()

    def test_local_blacklist_first(self):
        from app.db import db_cursor
        with db_cursor() as cur:
            cur.execute("DELETE FROM filter_list")
        with patch.object(detectors, "get_enabled_list",
                          return_value=["6.6.6.6"]):
            kept, bad = detectors.ip_postfilter(["1.1.1.1", "6.6.6.6"])
        assert kept == ["1.1.1.1"] and bad == ["6.6.6.6"]

    def test_parallel_multi_ip(self):
        """多 IP 并行：全部未命中（走缓存）时 kept 完整、顺序保持。"""
        for i in range(1, 5):
            ip_cache.put(f"10.0.0.{i}", False, "cached")
        with patch.object(detectors, "get_enabled_list", return_value=[]):
            kept, bad = detectors.ip_postfilter(
                ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"])
        assert kept == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
        assert bad == []

    def test_partial_malicious(self):
        ip_cache.put("10.0.0.1", False, "cached")
        ip_cache.put("10.0.0.2", True, "cached-bad")
        with patch.object(detectors, "get_enabled_list", return_value=[]):
            kept, bad = detectors.ip_postfilter(["10.0.0.1", "10.0.0.2"])
        assert kept == ["10.0.0.1"] and bad == ["10.0.0.2"]


# ---------------------------------------------------------------------------
# B4: 单次上游往返
# ---------------------------------------------------------------------------

class TestSingleUpstreamRoundtrip:
    """全正常路径只打一次上游（原实现 query_upstream + query_upstream_reply 共两次）。"""

    def _make_reply(self, request, ips):
        reply = request.reply()
        reply.header.rcode = RCODE.NOERROR
        for ip in ips:
            reply.add_answer(RR(request.q.qname, QTYPE.A, ttl=60, rdata=A(ip)))
        return reply

    def test_allow_path_single_upstream_call(self):
        upstream_calls = []

        def _fake_reply(request):
            upstream_calls.append(str(request.q.qname))
            return self._make_reply(request, ["203.0.113.10", "203.0.113.11"])

        q = DNSRecord.question("ok.example.com", "A")
        with patch.object(detectors, "query_upstream_reply",
                          side_effect=_fake_reply), \
             patch.object(detectors, "get_enabled_adapters", return_value=[]), \
             patch.object(detectors, "get_enabled_list", return_value=[]):
            reply = detectors.process_query(q)
        assert upstream_calls == ["ok.example.com."]    # 仅一次（dnslib qname 带尾点）
        assert len(reply.rr) == 2                        # 原始应答直接返回
        assert reply.header.rcode == RCODE.NOERROR

    def test_upstream_servfail_passthrough(self):
        def _fake_reply(request):
            r = request.reply()
            r.header.rcode = RCODE.SERVFAIL
            return r

        with patch.object(detectors, "query_upstream_reply",
                          side_effect=_fake_reply), \
             patch.object(detectors, "get_enabled_adapters", return_value=[]), \
             patch.object(detectors, "get_enabled_list", return_value=[]):
            reply = detectors.process_query(DNSRecord.question("x.example.com", "A"))
        assert reply.header.rcode == RCODE.SERVFAIL

    def test_no_answer_record_passthrough(self):
        """AAAA 无记录（NOERROR 空 ANSWER）：原样透传不拦截。"""
        def _fake_reply(request):
            return request.reply()

        with patch.object(detectors, "query_upstream_reply",
                          side_effect=_fake_reply), \
             patch.object(detectors, "get_enabled_adapters", return_value=[]), \
             patch.object(detectors, "get_enabled_list", return_value=[]):
            reply = detectors.process_query(DNSRecord.question("v6.example.com", "AAAA"))
        assert reply.header.rcode == RCODE.NOERROR
        assert len(reply.rr) == 0


# ---------------------------------------------------------------------------
# C5: cross_sync 跨进程轮询
# ---------------------------------------------------------------------------

class TestCrossSync:
    def setup_method(self):
        cross_sync.reset_baseline()
        cross_sync.poll_once()                     # 建立基线

    def test_no_change_no_action(self):
        assert cross_sync.poll_once() == {}

    def test_filter_list_change_triggers_invalidate(self):
        from app.db import db_cursor, invalidate_list_cache, get_enabled_list
        # 预热 list 缓存（写入旧值）
        with db_cursor() as cur:
            cur.execute("DELETE FROM filter_list")
            cur.execute("""INSERT INTO filter_list (list_type, target, value, enabled)
                           VALUES ('blacklist','domain','sync-test.example.com',1)""")
        get_enabled_list("blacklist", "domain")    # 缓存建立
        # 模拟 Web 进程新增（updated_at 用 strftime 保证与基线不同）
        time.sleep(1.1)                            # datetime 秒级粒度
        with db_cursor() as cur:
            cur.execute("""INSERT INTO filter_list (list_type, target, value, enabled)
                           VALUES ('blacklist','domain','sync-test2.example.com',1)""")
        changed = cross_sync.poll_once()
        assert changed.get("filter_list") is True
        # 缓存已失效重建：新条目可见
        vals = get_enabled_list("blacklist", "domain")
        assert "sync-test2.example.com" in vals
        with db_cursor() as cur:
            cur.execute("DELETE FROM filter_list WHERE value LIKE 'sync-test%'")

    def test_threatintel_change_clears_caches(self):
        from app.db import db_cursor
        # conftest 临时库不跑 seed，先造一行（模拟 Web 进程管理情报源）
        with db_cursor() as cur:
            cur.execute("""INSERT OR IGNORE INTO threatintel_api
                           (name, adapter_type, base_url, enabled, is_builtin)
                           VALUES ('cross_sync_probe', 'dnsbl', '', 0, 0)""")
        cross_sync.poll_once()             # 建立含该行的基线
        domain_cache.put("probe.example.com", False, "stale")   # 造旧缓存
        time.sleep(1.1)                    # datetime 秒级粒度，确保 updated_at 变化
        with db_cursor() as cur:
            cur.execute("""UPDATE threatintel_api
                           SET updated_at=datetime('now','localtime')
                           WHERE name='cross_sync_probe'""")
        changed = cross_sync.poll_once()
        if not changed:                    # 同秒兜底：写远期时间戳确保可观测
            with db_cursor() as cur:
                cur.execute("""UPDATE threatintel_api
                               SET updated_at='2099-01-01 00:00:00'
                               WHERE name='cross_sync_probe'""")
            changed = cross_sync.poll_once()
        assert changed.get("threatintel_api") is True
        assert domain_cache.get("probe.example.com") is None   # 缓存被联动清空
        with db_cursor() as cur:           # 清理探针行并重建基线
            cur.execute("DELETE FROM threatintel_api WHERE name='cross_sync_probe'")
        cross_sync.poll_once()

    def test_system_config_change_syncs(self):
        time.sleep(1.1)
        from app.runtime import set_config
        old = CONFIG.alert_ttl
        try:
            set_config("alert_ttl", str(min(old + 1, 86400)))
            changed = cross_sync.poll_once()
            assert changed.get("system_config") is True
        finally:
            set_config("alert_ttl", str(old))


# ---------------------------------------------------------------------------
# A2: seed 默认启用集
# ---------------------------------------------------------------------------

class TestSeedDefaultSources:
    def test_default_enabled_set(self):
        """生产默认 DNSBL 四源；测试环境（DNSF_TESTING=1）不默认启用。"""
        import os
        from seed import DEFAULT_ENABLED_SOURCES
        if os.environ.get("DNSF_TESTING") == "1":
            assert DEFAULT_ENABLED_SOURCES == set()
        else:
            assert DEFAULT_ENABLED_SOURCES == {
                "spamhaus_zen", "spamhaus_dbl", "dronebl", "spfbl"}
