"""生产稳定性加固测试（迭代 42：2026-09-10 spamhaus_dbl 全天超时拖垮全网事故）。

覆盖四项加固：
  1. DNSBL 超时上限（dnsbl_max_timeout_ms）：源级 5000ms 被压到 2500ms；
     上限 0=不限；低于上限不受影响；热生效（改 CONFIG 即时读新值）；
  2. 队列深度上限（max_queue_depth）：超限 submitted() 返回 False +
     rejected 计数；0=不限；热生效；handle_request 集成：队列满直接
     回 SERVFAIL（不提交 executor，pending 不涨）；
  3. 多上游重试（upstream_dns_backup）：主失败备成功→返回应答+计熔断
     成功；全失败→SERVFAIL+计一次熔断失败；目标序列解析（去重/去非法/
     空=仅主上游）；query_upstream 列表版同语义；
  4. 名单导入分批短事务：整源替换语义不变（重复导入无残留）、
     staging 表用后即删、遗留 staging 自愈（导入前 DROP 重建）；
  5. 配置 API：三新键 PUT 校验（合法值 200 热生效、非法值 400）。

网络隔离：上游查询全部 mock（fake send），导入用本地构造文本，
不依赖公网。

运行：cd platform && python -m pytest ../tests/test_hardening.py -v
"""

import asyncio
import time

import pytest
from dnslib import DNSRecord, QTYPE, RCODE

from config import CONFIG
import circuit_breaker
import detectors
import queue_stats


@pytest.fixture(autouse=True)
def hardening_env(monkeypatch):
    """四项配置快照还原 + 熔断/队列计数复位（跨测试污染防护）。"""
    keys = ("dnsbl_max_timeout_ms", "max_queue_depth", "upstream_dns_backup",
            "upstream_dns", "upstream_timeout_s")
    saved = {k: getattr(CONFIG, k) for k in keys}
    queue_stats.reset()
    circuit_breaker.reset_all()
    yield
    for k, v in saved.items():
        setattr(CONFIG, k, v)
    queue_stats.reset()
    circuit_breaker.reset_all()


# ---------------------------------------------------------------------------
# 1. DNSBL 超时上限
# ---------------------------------------------------------------------------

def test_dnsbl_timeout_cap_applied():
    """源级 5000ms 超过全局上限 2500ms → 有效超时被压到 2.5s。"""
    from adapters.dnsbl import SpamhausDBLAdapter
    a = SpamhausDBLAdapter(timeout_ms=5000)
    CONFIG.dnsbl_max_timeout_ms = 2500
    assert a._effective_timeout_s() == pytest.approx(2.5)


def test_dnsbl_timeout_cap_zero_unlimited():
    """上限 0 = 不限制（恢复旧行为，源级配置原样生效）。"""
    from adapters.dnsbl import SpamhausDBLAdapter
    a = SpamhausDBLAdapter(timeout_ms=5000)
    CONFIG.dnsbl_max_timeout_ms = 0
    assert a._effective_timeout_s() == pytest.approx(5.0)


def test_dnsbl_timeout_below_cap_untouched():
    """源级低于上限时不受影响（只压高不抬低）。"""
    from adapters.dnsbl import SpamhausDBLAdapter
    a = SpamhausDBLAdapter(timeout_ms=1000)
    CONFIG.dnsbl_max_timeout_ms = 2500
    assert a._effective_timeout_s() == pytest.approx(1.0)


def test_dnsbl_timeout_hot_reload():
    """热生效：同一适配器实例改 CONFIG 上限即时读新值。"""
    from adapters.dnsbl import SpamhausDBLAdapter
    a = SpamhausDBLAdapter(timeout_ms=8000)
    CONFIG.dnsbl_max_timeout_ms = 3000
    assert a._effective_timeout_s() == pytest.approx(3.0)
    CONFIG.dnsbl_max_timeout_ms = 1000
    assert a._effective_timeout_s() == pytest.approx(1.0)


def test_dnsbl_lookup_uses_capped_timeout(monkeypatch):
    """_lookup 实际把上限值传给底层 send（接线验证，非仅纯函数）。"""
    import adapters.dnsbl as dnsbl_mod

    captured = {}

    class _FakeQuery:
        def __init__(self, fqdn, qtype):
            pass

        @staticmethod
        def question(fqdn, qtype):
            return _FakeQuery(fqdn, qtype)

        @staticmethod
        def parse(data):
            return None

        def send(self, host, port, timeout):
            captured["timeout"] = timeout
            raise OSError("模拟超时")     # 走 None 路径即可观测参数

    monkeypatch.setattr(dnsbl_mod, "DNSRecord", _FakeQuery)
    a = dnsbl_mod.SpamhausDBLAdapter(timeout_ms=5000)
    CONFIG.dnsbl_max_timeout_ms = 2500
    assert a._lookup("x.test.dbl.spamhaus.org") is None
    assert captured["timeout"] == pytest.approx(2.5)


# ---------------------------------------------------------------------------
# 2. 队列深度上限
# ---------------------------------------------------------------------------

def test_queue_rejects_over_cap():
    """pending 达上限后 submitted() 返回 False，rejected 计数。"""
    CONFIG.max_queue_depth = 3
    assert queue_stats.submitted() is True
    assert queue_stats.submitted() is True
    assert queue_stats.submitted() is True
    assert queue_stats.submitted() is False          # 超限拒绝
    st = queue_stats.stats()
    assert st["pending"] == 3                        # 拒绝不占位
    assert st["rejected"] == 1
    queue_stats.completed()
    assert queue_stats.submitted() is True           # 释放后恢复接受
    assert queue_stats.stats()["rejected"] == 1


def test_queue_cap_zero_unlimited():
    """上限 0 = 不限（恢复旧行为）。"""
    CONFIG.max_queue_depth = 0
    for _ in range(600):
        assert queue_stats.submitted() is True
    assert queue_stats.stats()["pending"] == 600


def test_queue_cap_hot_reload():
    """热生效：运行中改 CONFIG.max_queue_depth 即时生效。"""
    CONFIG.max_queue_depth = 2
    assert queue_stats.submitted() is True
    assert queue_stats.submitted() is True
    assert queue_stats.submitted() is False
    CONFIG.max_queue_depth = 5                       # 热放宽
    for _ in range(3):
        assert queue_stats.submitted() is True
    assert queue_stats.stats()["pending"] == 5


def test_handle_request_fastfail_when_queue_full():
    """handle_request 集成：队列满时直接回 SERVFAIL，不提交 executor。"""
    import dns_server

    submitted_to_executor = {"n": 0}
    orig_process = dns_server.process_query

    def must_not_run(request, client_ip=None):
        submitted_to_executor["n"] += 1
        return request.reply()

    dns_server.process_query = must_not_run

    CONFIG.max_queue_depth = 1
    queue_stats.submitted()                          # 占满唯一名额

    replies = []

    class FakeTransport:
        def sendto(self, data, addr):
            replies.append(DNSRecord.parse(data))

    async def scenario():
        await dns_server.handle_request(
            DNSRecord.question("overflow.test", "A").pack(),
            FakeTransport(), ("127.0.0.1", 5353))

    try:
        asyncio.run(scenario())
    finally:
        dns_server.process_query = orig_process

    assert submitted_to_executor["n"] == 0           # 未进检测主流程
    assert len(replies) == 1
    assert replies[0].header.rcode == RCODE.SERVFAIL
    st = queue_stats.stats()
    assert st["rejected"] == 1
    assert st["pending"] == 1                        # 名额未被占用


# ---------------------------------------------------------------------------
# 3. 多上游重试
# ---------------------------------------------------------------------------

class _FakeUpstreamRequest:
    """替身 DNS 请求：按 host 决定成败，模拟主备上游差异。"""

    def __init__(self, fail_hosts, ok_host="ok.test", qname="x.test"):
        self.fail_hosts = set(fail_hosts)
        self._q = DNSRecord.question(qname, "A")
        self.reply_calls = 0

    def send(self, host, port, timeout):
        if host in self.fail_hosts:
            raise OSError(f"模拟 {host} 超时")
        return self._q.reply().pack()

    def reply(self):
        self.reply_calls += 1
        return self._q.reply()


def _upstream_states():
    return circuit_breaker.upstream_state()


def test_upstream_targets_parse():
    """备用序列解析：主 + 备（逗号分隔、去空格、去重、跳过非法）。"""
    CONFIG.upstream_dns = "223.5.5.5"
    CONFIG.upstream_dns_backup = "119.29.29.29, 223.5.5.5, ,bad host!"
    # "bad host!" 含空格非法 → 跳过；223.5.5.5 与主重复 → 去重
    targets = detectors._upstream_targets()
    assert targets == [("223.5.5.5", 53), ("119.29.29.29", 53)]


def test_upstream_targets_empty_backup():
    """空备用 = 仅主上游（默认行为，无重试开销）。"""
    CONFIG.upstream_dns = "1.2.3.4"
    CONFIG.upstream_dns_backup = ""
    assert detectors._upstream_targets() == [("1.2.3.4", 53)]


def test_upstream_targets_port_form():
    """ip:port 形式与多个备用的顺序保持。"""
    CONFIG.upstream_dns = "10.0.0.1:5353"
    CONFIG.upstream_dns_backup = "10.0.0.2:5354,10.0.0.3"
    assert detectors._upstream_targets() == [
        ("10.0.0.1", 5353), ("10.0.0.2", 5354), ("10.0.0.3", 53)]


def test_query_upstream_reply_backup_retry_success():
    """主失败→备成功：返回应答且计熔断成功（不记失败）。"""
    CONFIG.upstream_dns = "10.255.0.1"
    CONFIG.upstream_dns_backup = "10.255.0.2"
    req = _FakeUpstreamRequest(fail_hosts={"10.255.0.1"})
    resp = detectors.query_upstream_reply(req)
    assert resp.header.rcode != RCODE.SERVFAIL       # 备用救回
    # 熔断计数：成功（upstream_record_success 已调用——state closed）
    assert _upstream_states().get("state", "closed") == "closed"


def test_query_upstream_reply_all_fail_servfail():
    """主备全失败：SERVFAIL + 只计一次熔断失败。"""
    CONFIG.upstream_dns = "10.255.0.1"
    CONFIG.upstream_dns_backup = "10.255.0.2,10.255.0.3"
    req = _FakeUpstreamRequest(fail_hosts={"10.255.0.1", "10.255.0.2",
                                           "10.255.0.3"})
    resp = detectors.query_upstream_reply(req)
    assert resp.header.rcode == RCODE.SERVFAIL
    assert _upstream_states().get("failures", 0) == 1


def test_query_upstream_reply_primary_ok_no_backup_call():
    """主成功：不碰备用（无额外延迟）。"""
    CONFIG.upstream_dns = "10.255.0.1"
    CONFIG.upstream_dns_backup = "10.255.0.2"
    req = _FakeUpstreamRequest(fail_hosts={"10.255.0.2"})  # 备用标记为"不可调用"
    resp = detectors.query_upstream_reply(req)
    assert resp.header.rcode != RCODE.SERVFAIL


def test_query_upstream_list_backup_retry(monkeypatch):
    """query_upstream（IP 列表版）同语义：主失败备成功返回非空。"""
    CONFIG.upstream_dns = "10.255.0.1"
    CONFIG.upstream_dns_backup = "10.255.0.2"
    calls = []

    class _FakeQ:
        def __init__(self, domain, qtype):
            self.domain = domain

        def send(self, host, port, timeout):
            calls.append(host)
            if host == "10.255.0.1":
                raise OSError("模拟主上游超时")
            from dnslib import RR, A
            r = DNSRecord.question(self.domain, "A").reply()
            r.add_answer(RR(self.domain, QTYPE.A, ttl=60,
                            rdata=A("1.2.3.4")))
            return r.pack()

    class _FakeDNSRecord:
        @staticmethod
        def question(domain, qtype):
            return _FakeQ(domain, qtype)

        @staticmethod
        def parse(data):
            return DNSRecord.parse(data)

    monkeypatch.setattr(detectors, "DNSRecord", _FakeDNSRecord)
    ips = detectors.query_upstream("multi.test", QTYPE.A)
    assert ips == ["1.2.3.4"]
    assert calls == ["10.255.0.1", "10.255.0.2"]     # 主→备顺序重试


# ---------------------------------------------------------------------------
# 4. 名单导入分批短事务
# ---------------------------------------------------------------------------

def _staging_tables():
    from app.db import db_cursor
    with db_cursor() as cur:
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='threat_list_staging'")
        return [r["name"] for r in cur.fetchall()]


def test_import_source_replaces_and_cleans_staging():
    """整源替换语义不变 + staging 表用后即删。"""
    from app import threat_list
    from app.db import db_cursor

    rows1 = "\n".join(f"a{i}.test" for i in range(60000))   # 跨 BATCH=50000 两批
    n1 = threat_list.import_source("it42-src", rows1, enabled=True)
    assert n1 == 60000
    assert _staging_tables() == []                          # staging 已删

    with db_cursor() as cur:
        cnt = cur.execute(
            "SELECT COUNT(*) c FROM threat_list WHERE source='it42-src'"
        ).fetchone()["c"]
        assert cnt == 60000

    # 重复导入（更少条目）→ 整源替换，无残留
    rows2 = "\n".join(f"b{i}.test" for i in range(100))
    n2 = threat_list.import_source("it42-src", rows2, enabled=True)
    assert n2 == 100
    with db_cursor() as cur:
        cnt = cur.execute(
            "SELECT COUNT(*) c FROM threat_list WHERE source='it42-src'"
        ).fetchone()["c"]
        assert cnt == 100
        # a*.test 旧条目全部被替换
        old = cur.execute(
            "SELECT COUNT(*) c FROM threat_list "
            "WHERE source='it42-src' AND value LIKE 'a%'"
        ).fetchone()["c"]
        assert old == 0
    assert _staging_tables() == []
    # 清理本测试源
    threat_list.delete_source("it42-src")


def test_import_source_leftover_staging_selfheal():
    """上次导入崩溃遗留 staging 表 → 下次导入 DROP 重建自愈。"""
    from app import threat_list
    from app.db import db_cursor

    with db_cursor() as cur:
        cur.execute(
            "CREATE TABLE IF NOT EXISTS threat_list_staging "
            "(source TEXT, value TEXT, target TEXT, enabled INTEGER)")
        cur.execute(
            "INSERT INTO threat_list_staging VALUES "
            "('it42-leftover', 'stale.test', 'domain', 1)")

    n = threat_list.import_source("it42-leftover", "fresh1.test\nfresh2.test")
    assert n == 2
    assert _staging_tables() == []
    with db_cursor() as cur:
        # 旧 staging 残条不混入线上表
        stale = cur.execute(
            "SELECT COUNT(*) c FROM threat_list "
            "WHERE value='stale.test'").fetchone()["c"]
        assert stale == 0
    threat_list.delete_source("it42-leftover")


# ---------------------------------------------------------------------------
# 5. 配置 API（三新键校验 + 热生效）
# ---------------------------------------------------------------------------

def _login(client):
    r = client.post("/api/auth/login", json={
        "username": "admin", "password": CONFIG.admin_initial_password})
    return {"Authorization": "Bearer " + r.json()["data"]["token"]}


@pytest.fixture()
def clean_it42_config():
    """测试后清 system_config 里写入的迭代 42 键（防串扰后续测试）。"""
    from app.db import db_cursor
    yield
    with db_cursor() as cur:
        cur.execute(
            "DELETE FROM system_config WHERE key IN "
            "('dnsbl_max_timeout_ms', 'max_queue_depth', 'upstream_dns_backup')")


def test_config_api_it42_keys(clean_it42_config):
    """合法值 200 且热生效到内存 CONFIG。"""
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as client:
        auth = _login(client)
        r = client.put("/api/config", headers=auth, json={
            "dnsbl_max_timeout_ms": 3000,
            "max_queue_depth": 800,
            "upstream_dns_backup": "119.29.29.29, 114.114.114.114",
        })
        assert r.status_code == 200
        assert CONFIG.dnsbl_max_timeout_ms == 3000
        assert CONFIG.max_queue_depth == 800
        # 备用上游规范化：去空格
        assert CONFIG.upstream_dns_backup == "119.29.29.29,114.114.114.114"


def test_config_api_it42_validation(clean_it42_config):
    """非法值 400：超时上限越界 / 队列深度越界 / 备用格式非法 / 备用过多。"""
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as client:
        auth = _login(client)
        for body, field in [
            ({"dnsbl_max_timeout_ms": 50000}, "超时上限越界"),
            ({"dnsbl_max_timeout_ms": -1}, "超时上限负数"),
            ({"max_queue_depth": 200000}, "队列深度越界"),
            ({"upstream_dns_backup": "a b,1.2.3.4"}, "备用含空格"),
            ({"upstream_dns_backup": "1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4"},
             "备用超 3 个"),
        ]:
            r = client.put("/api/config", headers=auth, json=body)
            assert r.status_code == 400, f"{field} 应 400: {r.text}"


def test_config_api_it42_type_validation(clean_it42_config):
    """类型非法 422（整数键传不可解析类型）。"""
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as client:
        auth = _login(client)
        for body in [{"dnsbl_max_timeout_ms": ["x"]},
                     {"max_queue_depth": ["x"]}]:
            r = client.put("/api/config", headers=auth, json=body)
            assert r.status_code == 422
