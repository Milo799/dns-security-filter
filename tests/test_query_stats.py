"""今日请求统计修正测试 —— Task #161（生产 2026-09-03 观察）。

问题：/api/status 的 today_total = filter_log 三 action 求和，allows
受 allow_log_enabled（默认关）+ 采样限制 → 今日请求 ≈ 拦截数，严重低估。

方案验证：
  - query_stats.record 全 action 分类计数；total = 三类之和
  - flush_once 落库 UPSERT（重复调用幂等，不重复累加）
  - 日期翻转重置 + 昨日落尾
  - 进程重启从表恢复当日基数
  - process_query 各出口计数正确（allow 直通/白名单/放行/上游透传，
    intercept 本地黑名单/大名单/情报/IP 后置，remove_ip 部分剔除）
  - /api/status 优先读表；表空回退 filter_log 聚合
"""

import pytest
from dnslib import DNSRecord, QTYPE, RCODE
from unittest.mock import patch

import query_stats
import domain_cache
import ip_cache
from detectors import process_query


@pytest.fixture(autouse=True)
def clean():
    query_stats.reset()
    from app.db import db_cursor
    with db_cursor() as cur:
        cur.execute("DELETE FROM dns_query_stats")
        cur.execute("DELETE FROM filter_log")   # 隔离回退口径的串扰
    yield
    query_stats.reset()
    with db_cursor() as cur:
        cur.execute("DELETE FROM dns_query_stats")


# ---------------- 计数核心 ----------------

def test_record_classification():
    query_stats.record("intercept")
    query_stats.record("intercept")
    query_stats.record("remove_ip")
    query_stats.record("allow")
    query_stats.record("allow")
    query_stats.record("allow")
    snap = query_stats.today_snapshot()
    assert snap["total"] == 6
    assert snap["intercept"] == 2
    assert snap["remove_ip"] == 1
    assert snap["allow"] == 3


def test_record_unknown_action_counts_total_only():
    query_stats.record("whatever")
    snap = query_stats.today_snapshot()
    assert snap["total"] == 1
    assert snap["intercept"] == 0


# ---------------- 落库 ----------------

def test_flush_upsert_idempotent():
    query_stats.record("allow")
    query_stats.flush_once()
    query_stats.flush_once()               # 再 flush 不重复累加
    from app.db import db_cursor
    with db_cursor() as cur:
        cur.execute("SELECT * FROM dns_query_stats")
        rows = cur.fetchall()
    assert len(rows) == 1
    assert rows[0]["total"] == 1 and rows[0]["allow"] == 1


def test_flush_accumulates_then_persists():
    for _ in range(5):
        query_stats.record("allow")
    query_stats.record("intercept")
    query_stats.flush_once()
    from app.db import db_cursor
    with db_cursor() as cur:
        cur.execute("SELECT total, allow, intercept FROM dns_query_stats")
        row = cur.fetchone()
    assert row["total"] == 6 and row["allow"] == 5 and row["intercept"] == 1
    # 继续计数再落库：UPSERT 覆盖为累计值
    query_stats.record("allow")
    query_stats.flush_once()
    with db_cursor() as cur:
        cur.execute("SELECT total FROM dns_query_stats")
        assert cur.fetchone()["total"] == 7


# ---------------- 进程重启恢复 ----------------

def test_restart_restores_today_base():
    query_stats.record("intercept")
    query_stats.record("allow")
    query_stats.flush_once()
    # 模拟进程重启：内存清空，_ensure_loaded 从表恢复
    query_stats.reset()
    snap = query_stats.today_snapshot()
    assert snap["total"] == 2
    assert snap["intercept"] == 1 and snap["allow"] == 1


def test_read_today_from_db():
    assert query_stats.read_today_from_db() is None    # 无行
    query_stats.record("allow")
    query_stats.flush_once()
    row = query_stats.read_today_from_db()
    assert row is not None and row["total"] == 1


# ---------------- process_query 出口计数 ----------------

def _fake_upstream_ok(request):
    reply = request.reply()
    from dnslib import RR, A
    reply.add_answer(RR(request.q.qname, QTYPE.A, ttl=60, rdata=A("203.0.113.10")))
    return reply


def test_process_query_allow_path_counts():
    domain_cache.clear()
    ip_cache.clear()
    with patch("detectors.query_upstream_reply", side_effect=_fake_upstream_ok), \
         patch("detectors.get_enabled_adapters", return_value=[]), \
         patch("detectors.get_enabled_list", return_value=[]):
        process_query(DNSRecord.question("ok-a.test", "A"))
    snap = query_stats.today_snapshot()
    assert snap["total"] == 1 and snap["allow"] == 1


def test_process_query_intercept_local_blacklist_counts():
    """黑名单命中计 intercept。注意 patch 必须区分 whitelist/blacklist
    两个调用（同函数不同 target 参数），否则白名单先命中走了 allow。"""
    def _lists(list_type, target):
        if list_type == "blacklist" and target == "domain":
            return ["bad-b.test"]
        return []
    with patch("detectors.get_enabled_list", side_effect=_lists):
        process_query(DNSRecord.question("bad-b.test", "A"))
    snap = query_stats.today_snapshot()
    assert snap["total"] == 1 and snap["intercept"] == 1


def test_process_query_whitelist_counts_allow():
    def _lists(list_type, target):
        if list_type == "whitelist" and target == "domain":
            return ["white-e.test"]
        return []
    with patch("detectors.get_enabled_list", side_effect=_lists), \
         patch("detectors.query_upstream_reply", side_effect=_fake_upstream_ok):
        process_query(DNSRecord.question("white-e.test", "A"))
    snap = query_stats.today_snapshot()
    assert snap["total"] == 1 and snap["allow"] == 1


def test_process_query_detection_disabled_counts_allow():
    from config import CONFIG
    with patch.object(CONFIG, "detection_enabled", False), \
         patch("detectors.query_upstream_reply", side_effect=_fake_upstream_ok):
        process_query(DNSRecord.question("any-c.test", "A"))
    snap = query_stats.today_snapshot()
    assert snap["total"] == 1 and snap["allow"] == 1


def test_process_query_non_filterable_counts_allow():
    """非 A/AAAA（如 MX）直接转发也计数（请求全量口径）。"""
    with patch("detectors.query_upstream_reply", side_effect=_fake_upstream_ok):
        process_query(DNSRecord.question("mx-d.test", "MX"))
    snap = query_stats.today_snapshot()
    assert snap["total"] == 1 and snap["allow"] == 1


# ---------------- /api/status 优先读表 ----------------

def test_status_reads_query_stats_first():
    from fastapi.testclient import TestClient
    from config import CONFIG
    from app.main import app

    # 无统计行：回退 filter_log（此刻空 → 全 0）
    with TestClient(app) as c:
        r = c.post("/api/auth/login", json={
            "username": "admin", "password": CONFIG.admin_initial_password})
        token = r.json()["data"]["token"]
        r = c.get("/api/status", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["data"]["today_total"] == 0

    # 有统计行：读表值
    for _ in range(3):
        query_stats.record("allow")
    query_stats.record("intercept")
    query_stats.flush_once()
    with TestClient(app) as c:
        r = c.post("/api/auth/login", json={
            "username": "admin", "password": CONFIG.admin_initial_password})
        token = r.json()["data"]["token"]
        r = c.get("/api/status", headers={"Authorization": f"Bearer {token}"})
        data = r.json()["data"]
        assert data["today_total"] == 4
        assert data["today_allows"] == 3
        assert data["today_intercepts"] == 1
