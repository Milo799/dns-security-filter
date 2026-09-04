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
        # Task #166：口径来源标记（前端据此展示口径，防误导）
        assert data["stats_source"] == "query_stats"


# ---------------- Task #166：trend 口径修正 ----------------

def test_trend_stats_source_and_prioritized_table():
    """trend 优先读 dns_query_stats；表空回退 filter_log 并标记来源。"""
    from fastapi.testclient import TestClient
    from config import CONFIG
    from app.main import app
    from datetime import date, timedelta

    with TestClient(app) as c:
        r = c.post("/api/auth/login", json={
            "username": "admin", "password": CONFIG.admin_initial_password})
        token = r.json()["data"]["token"]
        h = {"Authorization": f"Bearer {token}"}

        # 场景 1：无统计行 → filter_log 回退
        r = c.get("/api/status/trend", headers=h)
        assert r.status_code == 200
        d = r.json()["data"]
        assert d["stats_source"] == "filter_log"

        # 场景 2：有统计行 → query_stats 口径 + 环比专用字段
        from app.db import db_cursor
        today = date.today().isoformat()
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        with db_cursor() as cur:
            cur.execute(
                "INSERT INTO dns_query_stats (date,total,intercept,remove_ip,allow) "
                "VALUES (?,?,?,?,?)",
                (yesterday, 100, 80, 5, 15))
            cur.execute(
                "INSERT INTO dns_query_stats (date,total,intercept,remove_ip,allow) "
                "VALUES (?,?,?,?,?)",
                (today, 40, 30, 2, 8))
        r = c.get("/api/status/trend", headers=h)
        d = r.json()["data"]
        assert d["stats_source"] == "query_stats"
        assert d["today"]["date"] == today
        assert d["today"]["intercept"] == 30
        assert d["yesterday"]["date"] == yesterday
        assert d["yesterday"]["intercept"] == 80
        # 已过时长在 [0,24)
        assert 0 <= d["today_elapsed_hours"] < 24
        # 今日是进行中的部分天：full_days 不含今日，含昨日
        assert today not in d["full_days"]
        assert yesterday in d["full_days"]


def test_trend_localtime_window_no_utc_drift():
    """UTC+8 环境下窗口边界必须用 localtime：UTC 起点会把
    '昨天的本地晚间数据'排除在 N 日窗口外（迭代 26 修正回归锚）。"""
    from fastapi.testclient import TestClient
    from config import CONFIG
    from app.main import app
    from datetime import datetime, timedelta

    # 直接造一条 26 小时前的本地时间日志（7 日窗口必须包含）
    ts = (datetime.now() - timedelta(hours=26)).strftime("%Y-%m-%d %H:%M:%S")
    from app.db import db_cursor
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO filter_log
               (client_ip, domain, query_type, filter_reason, action,
                malicious_ips, final_result, source_api, timestamp)
               VALUES ('', 'trend-utc.test', 'A', 'local_blacklist',
                       'intercept', '', '', '', ?)""", (ts,))

    with TestClient(app) as c:
        r = c.post("/api/auth/login", json={
            "username": "admin", "password": CONFIG.admin_initial_password})
        token = r.json()["data"]["token"]
        r = c.get("/api/status/trend?days=7", headers={
            "Authorization": f"Bearer {token}"})
        d = r.json()["data"]
        # filter_log 回退口径下（无统计行）26h 前的行必须被聚合到
        total_intercepts = sum(it["intercept"] for it in d["items"])
        assert total_intercepts >= 1


def test_breakdown_localtime_window():
    """breakdown 的 sources/top_domains 窗口也须 localtime（旧实现
    UTC 起点，与同端点 top_clients 的 localtime 不一致）。"""
    from fastapi.testclient import TestClient
    from config import CONFIG
    from app.main import app
    from datetime import datetime, timedelta

    ts = (datetime.now() - timedelta(hours=26)).strftime("%Y-%m-%d %H:%M:%S")
    from app.db import db_cursor
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO filter_log
               (client_ip, domain, query_type, filter_reason, action,
                malicious_ips, final_result, source_api, timestamp)
               VALUES ('10.1.1.1', 'bd-utc.test', 'A', 'local_blacklist',
                       'intercept', '', '', '', ?)""", (ts,))
    with TestClient(app) as c:
        r = c.post("/api/auth/login", json={
            "username": "admin", "password": CONFIG.admin_initial_password})
        token = r.json()["data"]["token"]
        r = c.get("/api/status/breakdown?days=7", headers={
            "Authorization": f"Bearer {token}"})
        d = r.json()["data"]
        by = {s["key"]: s["count"] for s in d["sources"]}
        assert by["local_blacklist"] >= 1
        assert any(t["domain"] == "bd-utc.test" for t in d["top_domains"])
        assert any(c["client_ip"] == "10.1.1.1" for c in d["top_clients"])


# ---------------- Task #175（迭代 28）：安全态势其余卡片口径 ----------------

def test_stream_excludes_allow():
    """事件流端点只含拦截/剔除：allow 采样日志混入会被渲染成
    "拦截"（语义错误），且无 COUNT 全表扫描。"""
    from fastapi.testclient import TestClient
    from config import CONFIG
    from app.main import app
    from app.db import db_cursor

    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO filter_log
               (client_ip, domain, query_type, filter_reason, action,
                malicious_ips, final_result, source_api)
               VALUES ('', 'st-int.test', 'A', 'local_blacklist', 'intercept',
                       '', '', ''),
                      ('', 'st-allow.test', 'A', 'allow', 'allow',
                       '', 'forwarded', ''),
                      ('', 'st-rm.test', 'A', 'ip_filter', 'remove_ip',
                       '1.1.1.1', '', '')""")
    with TestClient(app) as c:
        r = c.post("/api/auth/login", json={
            "username": "admin", "password": CONFIG.admin_initial_password})
        token = r.json()["data"]["token"]
        r = c.get("/api/logs/stream?size=8", headers={
            "Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        items = r.json()["data"]["items"]
        actions = {it["action"] for it in items}
        assert "allow" not in actions
        assert "intercept" in actions and "remove_ip" in actions
        assert all(set(it.keys()) == set(
            ("id", "timestamp", "client_ip", "domain", "query_type",
             "filter_reason", "action", "malicious_ips", "final_result",
             "source_api")) for it in items)


def test_hourly_fill_zero_gaps():
    """24h 聚合必须补零连续小时：GROUP BY 只返回有数据的小时，
    缺行导致前端 X 轴失真（无数据小时被抽掉）。"""
    from fastapi.testclient import TestClient
    from config import CONFIG
    from app.main import app
    from app.db import db_cursor
    from datetime import datetime, timedelta

    # 只造 1 小时数据（23 小时静默）
    ts = (datetime.now() - timedelta(hours=2)).strftime(
        "%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO filter_log
               (client_ip, domain, query_type, filter_reason, action,
                malicious_ips, final_result, source_api, timestamp)
               VALUES ('', 'hz-1.test', 'A', 'local_blacklist', 'intercept',
                       '', '', '', ?)""", (ts,))

    with TestClient(app) as c:
        r = c.post("/api/auth/login", json={
            "username": "admin", "password": CONFIG.admin_initial_password})
        token = r.json()["data"]["token"]
        r = c.get("/api/status/hourly?hours=24", headers={
            "Authorization": f"Bearer {token}"})
        d = r.json()["data"]
        items = d["items"]
        assert len(items) == 24
        # 逐档连续：相邻项小时差恰为 1 小时（字符串比较即时间序）
        from datetime import datetime as _dt
        hours = [_dt.strptime(it["hour"], "%Y-%m-%d %H:00")
                 for it in items]
        for a, b in zip(hours, hours[1:]):
            assert (b - a) == timedelta(hours=1)
        # 缺档补零、有数据档有值
        hit = [it for it in items if it["intercepts"] >= 1]
        assert len(hit) >= 1
        zeros = [it for it in items if it["intercepts"] == 0]
        assert len(zeros) >= 1
        # 每档字段完整
        assert all(it.get("threat_list") is not None
                   and it.get("threatintel") is not None
                   and it.get("ip_filter") is not None
                   for it in items)


def test_hourly_window_matches_fill_zero():
    """补零序列的窗口与聚合窗口一致：序列尾（最新档）必须是当前
    小时，26h 前的数据行不应出现在 24h 窗口内。"""
    from fastapi.testclient import TestClient
    from config import CONFIG
    from app.main import app
    from app.db import db_cursor
    from datetime import datetime, timedelta

    ts = (datetime.now() - timedelta(hours=26)).strftime(
        "%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO filter_log
               (client_ip, domain, query_type, filter_reason, action,
                malicious_ips, final_result, source_api, timestamp)
               VALUES ('', 'hz-out.test', 'A', 'local_blacklist', 'intercept',
                       '', '', '', ?)""", (ts,))

    with TestClient(app) as c:
        r = c.post("/api/auth/login", json={
            "username": "admin", "password": CONFIG.admin_initial_password})
        token = r.json()["data"]["token"]
        r = c.get("/api/status/hourly?hours=24", headers={
            "Authorization": f"Bearer {token}"})
        items = r.json()["data"]["items"]
        assert len(items) == 24
        # 24 档 = 当前整点往前推 23 档：首档恰为 (当前小时-23h)，
        # 26h 前的行不入窗（sum 为 0），窗口边界校准
        from datetime import datetime as _dt
        first = _dt.strptime(items[0]["hour"], "%Y-%m-%d %H:00")
        expect_first = datetime.now().replace(
            minute=0, second=0, microsecond=0) - timedelta(hours=23)
        assert first == expect_first
        vals = [it["intercepts"] for it in items]
        assert sum(vals) == 0
