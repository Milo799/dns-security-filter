"""迭代 36：重复查询计数消解（query_dedup）测试。

背景：生产"今日请求/放行"虚高，根因是 Windows DNS 转发器超时重发
同一查询被重复计数。query_dedup 按 (client_ip, domain, qtype) 做
N 秒滑动窗口去重——窗口内重发只计 1 次（检测与应答行为不变）。
"""

import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from dnslib import DNSRecord, QTYPE, RCODE

import query_dedup
import query_stats
import domain_cache
import ip_cache
from config import CONFIG
from detectors import process_query
from app.main import app


@pytest.fixture()
def client():
    with TestClient(app) as c:   # 触发 startup：建表 + seed + 配置同步
        # 迭代 31 后 API 全认证：登录拿 token 并注入头
        r = c.post("/api/auth/login",
                   json={"username": "admin", "password": "admin123"})
        token = r.json()["data"]["token"]
        c.headers.update({"Authorization": "Bearer " + token})
        yield c


@pytest.fixture(autouse=True)
def _reset_dedup():
    """每测试前后复位去重表与计数（防跨测试键串扰）。"""
    query_dedup.reset()
    query_stats.reset()
    domain_cache.clear()
    ip_cache.clear()
    yield
    query_dedup.reset()
    query_stats.reset()
    domain_cache.clear()
    ip_cache.clear()


def _q(domain="dup-test.example.com", qtype="A"):
    """构造查询。qtype 用字符串（dnslib DNSRecord.question 要求 str）。"""
    return DNSRecord.question(domain, qtype)


def _fake_upstream_ok(request):
    """上游正常应答（A 查询带一条 A 记录；其他 qtype 空应答 NOERROR）。"""
    from dnslib import RR, A
    reply = request.reply()
    if request.q.qtype == QTYPE.A:
        reply.add_answer(RR(request.q.qname, QTYPE.A, ttl=60, rdata=A("203.0.113.10")))
    return reply


def _patches():
    """检测链路 mock 三件套（上游应答/无在线源/空名单）。"""
    return [
        patch("detectors.query_upstream_reply", side_effect=_fake_upstream_ok),
        patch("detectors.get_enabled_adapters", return_value=[]),
        patch("detectors.get_enabled_list", return_value=[]),
    ]


# ---------------------------------------------------------------------------
# 1. 纯模块层：check_and_count 语义
# ---------------------------------------------------------------------------

class TestDedupModule:

    def test_first_query_counts(self):
        """首次查询 → False（正常计数）。"""
        assert query_dedup.check_and_count("1.1.1.1", "a.com", QTYPE.A) is False

    def test_duplicate_within_window_skipped(self):
        """窗口内同键重发 → True（跳过计数）。"""
        query_dedup.check_and_count("1.1.1.1", "a.com", QTYPE.A)
        assert query_dedup.check_and_count("1.1.1.1", "a.com", QTYPE.A) is True

    def test_different_client_not_dup(self):
        """不同 client_ip 的同域名查询 → 各自首次（转发器重发同源 IP，
        不同源查同域名是正常新查询）。"""
        query_dedup.check_and_count("1.1.1.1", "a.com", QTYPE.A)
        assert query_dedup.check_and_count("2.2.2.2", "a.com", QTYPE.A) is False

    def test_different_domain_not_dup(self):
        """同 client 不同域名 → 新查询。"""
        query_dedup.check_and_count("1.1.1.1", "a.com", QTYPE.A)
        assert query_dedup.check_and_count("1.1.1.1", "b.com", QTYPE.A) is False

    def test_different_qtype_not_dup(self):
        """同 client 同域名不同 qtype（A vs AAAA）→ 新查询。"""
        query_dedup.check_and_count("1.1.1.1", "a.com", QTYPE.A)
        assert query_dedup.check_and_count("1.1.1.1", "a.com", QTYPE.AAAA) is False

    def test_window_expiry_counts_again(self, monkeypatch):
        """窗口过期后同键再来 → 重新计数（滑窗不是永久抑制）。"""
        base = time.monotonic()
        monkeypatch.setattr(time, "monotonic", lambda: base)
        query_dedup.check_and_count("1.1.1.1", "a.com", QTYPE.A)
        # 快进 10s（默认窗口 3s）——注意先取 base 再引用，防无限递归
        monkeypatch.setattr(time, "monotonic", lambda: base + 10)
        assert query_dedup.check_and_count("1.1.1.1", "a.com", QTYPE.A) is False

    def test_disabled_never_dups(self, monkeypatch):
        """window=0 禁用 → 重发也照常计数。"""
        monkeypatch.setattr(CONFIG, "query_dedup_window_s", 0)
        query_dedup.check_and_count("1.1.1.1", "a.com", QTYPE.A)
        assert query_dedup.check_and_count("1.1.1.1", "a.com", QTYPE.A) is False
        assert query_dedup.check_and_count("1.1.1.1", "a.com", QTYPE.A) is False

    def test_stats_counts(self):
        """观测计数：deduped/passed 正确累计。"""
        query_dedup.check_and_count("1.1.1.1", "a.com", QTYPE.A)
        query_dedup.check_and_count("1.1.1.1", "a.com", QTYPE.A)
        query_dedup.check_and_count("2.2.2.2", "a.com", QTYPE.A)
        s = query_dedup.stats()
        assert s["deduped"] == 1
        assert s["passed"] == 2
        assert s["window_s"] == pytest.approx(3.0)
        assert s["entries"] == 2


# ---------------------------------------------------------------------------
# 2. 集成层：process_query 计数消解（检测行为不变）
# ---------------------------------------------------------------------------

class TestProcessQueryDedup:

    def test_duplicate_query_counted_once(self):
        """同一查询连续两次（模拟转发器重发）：total 只 +1，
        但两次都拿到正常应答（检测行为不变）。"""
        ps = _patches()
        for p in ps:
            p.start()
        try:
            r1 = process_query(_q(), client_ip="1.1.1.1")
            r2 = process_query(_q(), client_ip="1.1.1.1")
        finally:
            for p in ps:
                p.stop()
        snap = query_stats.today_snapshot()
        assert snap["total"] == 1                 # 计数消解实锤
        assert snap["allow"] == 1
        # 应答行为不变：两次都是正常 DNS 应答
        assert r1.header.rcode == RCODE.NOERROR
        assert r2.header.rcode == RCODE.NOERROR

    def test_different_clients_both_counted(self):
        """不同客户端查同域名 → 各自计数（正常流量不受影响）。"""
        ps = _patches()
        for p in ps:
            p.start()
        try:
            process_query(_q(), client_ip="1.1.1.1")
            process_query(_q(), client_ip="2.2.2.2")
        finally:
            for p in ps:
                p.stop()
        snap = query_stats.today_snapshot()
        assert snap["total"] == 2

    def test_disabled_window_counts_all(self, monkeypatch):
        """窗口禁用（0）→ 回退旧行为，重发也计数（逃生开关）。"""
        monkeypatch.setattr(CONFIG, "query_dedup_window_s", 0)
        ps = _patches()
        for p in ps:
            p.start()
        try:
            process_query(_q(), client_ip="1.1.1.1")
            process_query(_q(), client_ip="1.1.1.1")
        finally:
            for p in ps:
                p.stop()
        snap = query_stats.today_snapshot()
        assert snap["total"] == 2


# ---------------------------------------------------------------------------
# 3. 配置层：热生效与校验
# ---------------------------------------------------------------------------

class TestDedupConfig:

    def test_default_window_3s(self):
        """默认窗口 3 秒（覆盖 Windows 转发器 3~4s 重试窗口）。"""
        assert CONFIG.query_dedup_window_s == pytest.approx(3.0)

    def test_runtime_float_key_applied(self):
        """runtime._apply 浮点键：字符串值正确还原为 float。"""
        from app.runtime import _apply
        _apply("query_dedup_window_s", "5.5")
        assert CONFIG.query_dedup_window_s == pytest.approx(5.5)
        _apply("query_dedup_window_s", "3.0")     # 恢复默认，防污染后续测试

    def test_stats_endpoint_shape(self, client):
        """GET /api/query-dedup/stats 返回四字段快照。"""
        r = client.get("/api/query-dedup/stats")
        assert r.status_code == 200
        data = r.json()["data"]
        assert set(data) == {"window_s", "entries", "deduped", "passed"}

    def test_config_update_roundtrip(self, client, monkeypatch):
        """PUT /api/config 热更窗口值（校验+落库+CONFIG 生效）。"""
        r = client.put("/api/config", json={"query_dedup_window_s": 2.0})
        assert r.status_code == 200
        assert CONFIG.query_dedup_window_s == pytest.approx(2.0)
        # 恢复默认，防污染后续测试
        client.put("/api/config", json={"query_dedup_window_s": 3.0})
        assert CONFIG.query_dedup_window_s == pytest.approx(3.0)

    def test_config_validation_rejects_negative(self, client):
        """负值窗口被 400 拒绝（0~60 合法域）。"""
        r = client.put("/api/config", json={"query_dedup_window_s": -1})
        assert r.status_code == 400

    def test_config_validation_rejects_over_60(self, client):
        """超过 60s 被 400 拒绝（过长窗口会误吞正常重复查询）。"""
        r = client.put("/api/config", json={"query_dedup_window_s": 61})
        assert r.status_code == 400
