"""NRD 新注册域名检测层测试（迭代 40）。

覆盖：
  1. TLD 前置过滤（名单外零开销跳过、名单内进入检测）；
  2. whoisit 三态异常映射（UnsupportedError/ResourceDoesNotExist/
     QueryError → None 放行，绝不 fail-safe）；
  3. 注册时间永久缓存（内存 + SQLite，第二次查询不再发网络请求）；
  4. 年龄阈值边界（≤ nrd_max_age_days 判新）；
  5. observe 模式：命中只记日志不拦截（应答为上游正常解析）；
  6. intercept 模式：命中拦截（应答为 alert_ip，reason=nrd）；
  7. nrd_enabled=False 零开销（不发查询、不记日志）；
  8. 配置热生效（CONFIG 直改立即生效——DNS 进程每查询读 CONFIG）；
  9. /api/nrd/stats 端点；
 10. nrd_cache 表迁移（旧库启动自动建表）。

网络隔离：全部用 monkeypatch 替换 whoisit.domain / warm_bootstrap，
测试不依赖公网。

运行：cd platform && python -m pytest ../tests/test_nrd.py -v
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from dnslib import DNSRecord, QTYPE, RR, A, RCODE

import rdap_nrd
from config import CONFIG
from detectors import process_query
from app.db import db_cursor


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------

@pytest.fixture
def nrd_env(monkeypatch):
    """NRD 测试环境：关网络（bootstrap/whoisit.domain 全替换），还原配置。

    返回 dict：queries 列表记录 whoisit.domain 收到的域名（断言
    "是否真的发了网络查询"），fake_result 控制返回值，fake_exc 控制
    抛出的异常。
    """
    rdap_nrd.reset()
    state = {"queries": [], "result": None, "exc": None}

    def fake_warm():
        rdap_nrd._BOOTSTRAP_READY = True

    def fake_domain(d, **kw):
        state["queries"].append(d)
        if state["exc"] is not None:
            raise state["exc"]
        return {"registration_date": state["result"]}

    monkeypatch.setattr(rdap_nrd, "warm_bootstrap", fake_warm)
    monkeypatch.setattr(rdap_nrd.whoisit, "domain", fake_domain)

    # 隔离跨测试残留（全量套件下此前测试遗留）：
    #   - nrd_cache 行（串扰缓存断言）；
    #   - filter_list 黑名单（如 test_e2e 遗留的 93.184.216.0/24 会
    #     命中本套件 FakeUpstream 的应答 IP → IP 后置误拦）；
    #   - threatintel_api 启用源（testcenter 的 example 恒无结论 →
    #     fail-safe 误拦）。
    # filter_list 快照后清空、结束原样恢复（不破坏其他测试假设）。
    with db_cursor() as cur:
        cur.execute("DELETE FROM nrd_cache")
        cur.execute("SELECT * FROM filter_list")
        _saved_filter_list = [tuple(r) for r in cur.fetchall()]
        cur.execute("DELETE FROM filter_list")
        cur.execute("UPDATE threatintel_api SET enabled=0")

    saved = {k: getattr(CONFIG, k) for k in
             ("nrd_enabled", "nrd_mode", "nrd_max_age_days", "nrd_tlds")}
    CONFIG.nrd_enabled = True
    CONFIG.nrd_mode = "observe"
    CONFIG.nrd_max_age_days = 7
    CONFIG.nrd_tlds = "xyz,top,icu,shop,online,site,cfd,sbs,rest,cyou"
    yield state
    for k, v in saved.items():
        setattr(CONFIG, k, v)
    rdap_nrd.reset()
    # 恢复 filter_list 快照（INSERT OR REPLACE 按原主键写回）
    if _saved_filter_list:
        with db_cursor() as cur:
            placeholders = ",".join("?" * len(_saved_filter_list[0]))
            cur.executemany(
                f"INSERT OR REPLACE INTO filter_list VALUES ({placeholders})",
                _saved_filter_list)


class FakeUpstream:
    """线程 UDP 上游（test_e2e 同款）：A → 93.184.216.34。"""

    def __init__(self):
        import socket
        import threading
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.3)
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        import socket
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                req = DNSRecord.parse(data)
                reply = req.reply()
                if req.q.qtype == QTYPE.A:
                    reply.add_answer(RR(req.q.qname, QTYPE.A, ttl=60,
                                        rdata=A("93.184.216.34")))
                self.sock.sendto(reply.pack(), addr)
            except Exception:
                continue

    def close(self):
        self.running = False
        self.sock.close()


@pytest.fixture
def upstream():
    fu = FakeUpstream()
    old = CONFIG.upstream_dns
    CONFIG.upstream_dns = f"127.0.0.1:{fu.port}"
    yield fu
    CONFIG.upstream_dns = old
    fu.close()


def _query(domain: str) -> DNSRecord:
    return process_query(DNSRecord.question(domain, "A"),
                         client_ip="192.168.1.100")


def _read_log(domain: str) -> list[dict]:
    with db_cursor() as cur:
        cur.execute(
            "SELECT filter_reason, action, source_api FROM filter_log "
            "WHERE domain=? ORDER BY id DESC LIMIT 5", (domain,))
        return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# 1. TLD 前置过滤
# ---------------------------------------------------------------------------

def test_tld_filter_skips_unlisted(nrd_env):
    """名单外 TLD（.com/.cn）零网络开销跳过：不发查询。"""
    assert rdap_nrd.is_new_registration("www.example.com") is None
    assert rdap_nrd.is_new_registration("baidu.cn") is None
    assert nrd_env["queries"] == []
    assert rdap_nrd.stats()["skipped_tld"] == 2


def test_tld_filter_allows_listed(nrd_env):
    """名单内 TLD 进入检测（发 RDAP 查询）。"""
    nrd_env["result"] = datetime.now(timezone.utc) - timedelta(days=3)
    assert rdap_nrd.is_new_registration("evil-thing.xyz") is True
    assert nrd_env["queries"] == ["evil-thing.xyz"]


def test_tld_filter_empty_means_all(nrd_env):
    """nrd_tlds 置空 = 全部 TLD 都查（含 .com）。"""
    CONFIG.nrd_tlds = ""
    nrd_env["result"] = datetime.now(timezone.utc) - timedelta(days=30)
    assert rdap_nrd.is_new_registration("www.example.com") is False
    assert nrd_env["queries"] == ["www.example.com"]


# ---------------------------------------------------------------------------
# 2. whoisit 三态异常映射
# ---------------------------------------------------------------------------

def test_unsupported_error_returns_none(nrd_env):
    """.cn 等 TLD 无 RDAP 服务 → None 放行，绝不 fail-safe。"""
    nrd_env["exc"] = rdap_nrd.wi_errors.UnsupportedError("no RDAP for .cn")
    CONFIG.nrd_tlds = ""                    # 强制 .cn 进检测
    assert rdap_nrd.is_new_registration("baidu.cn") is None
    assert rdap_nrd.stats()["skipped_unsupported"] == 1
    # 无结论不落缓存：下次还会查（路由表可能更新）
    assert "baidu.cn" not in rdap_nrd._MEM_CACHE


def test_not_exist_returns_none(nrd_env):
    """域名未注册（ResourceDoesNotExist）→ None。"""
    nrd_env["exc"] = rdap_nrd.wi_errors.ResourceDoesNotExist("404")
    assert rdap_nrd.is_new_registration("unregistered-xyz-thing.xyz") is None
    assert rdap_nrd.stats()["skipped_notexist"] == 1


def test_query_error_returns_none(nrd_env):
    """真失败（QueryError/网络异常）→ None 放行，不计熔断失败。"""
    nrd_env["exc"] = rdap_nrd.wi_errors.QueryError("timeout")
    assert rdap_nrd.is_new_registration("slow-registry.xyz") is None
    assert rdap_nrd.stats()["skipped_error"] == 1


# ---------------------------------------------------------------------------
# 3. 永久缓存
# ---------------------------------------------------------------------------

def test_cache_persists_no_requery(nrd_env):
    """第二次查询走缓存：不再发网络请求。"""
    nrd_env["result"] = datetime.now(timezone.utc) - timedelta(days=3)
    rdap_nrd.is_new_registration("cached-once.xyz")
    assert len(nrd_env["queries"]) == 1
    # 第二次：缓存命中，零网络查询
    assert rdap_nrd.is_new_registration("cached-once.xyz") is True
    assert len(nrd_env["queries"]) == 1
    assert rdap_nrd.stats()["cache_hits"] == 1

    # 落库验证：nrd_cache 有行
    with db_cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM nrd_cache "
                    "WHERE domain='cached-once.xyz'")
        assert cur.fetchone()["n"] == 1


def test_cache_reloaded_from_db(nrd_env):
    """reset 后（模拟进程重启）从 nrd_cache 表重载：仍不发网络查询。"""
    nrd_env["result"] = datetime.now(timezone.utc) - timedelta(days=3)
    rdap_nrd.is_new_registration("persist-me.xyz")
    rdap_nrd.reset()                        # 清内存（_LOADED=False）
    nrd_env["queries"].clear()
    assert rdap_nrd.is_new_registration("persist-me.xyz") is True
    assert nrd_env["queries"] == []         # 全部来自 DB 缓存


# ---------------------------------------------------------------------------
# 4. 年龄阈值
# ---------------------------------------------------------------------------

def test_age_within_threshold(nrd_env):
    """3 天前注册 < 7 天阈值 → 新注册。"""
    nrd_env["result"] = datetime.now(timezone.utc) - timedelta(days=3)
    assert rdap_nrd.is_new_registration("fresh.xyz") is True


def test_age_beyond_threshold(nrd_env):
    """30 天前注册 > 7 天阈值 → 非新注册。"""
    nrd_env["result"] = datetime.now(timezone.utc) - timedelta(days=30)
    assert rdap_nrd.is_new_registration("old.xyz") is False


def test_age_boundary_inclusive(nrd_env):
    """恰好 7 天 = 阈值内（≤ 判新）。"""
    nrd_env["result"] = datetime.now(timezone.utc) - timedelta(days=7) \
        + timedelta(hours=1)
    assert rdap_nrd.is_new_registration("edge.xyz") is True


def test_future_registration_safe(nrd_env):
    """注册时间在未来（时钟偏差/脏数据）→ 年龄取 0 → 判新（保守）。"""
    nrd_env["result"] = datetime.now(timezone.utc) + timedelta(days=2)
    assert rdap_nrd.is_new_registration("future.xyz") is True


def test_no_registration_date_field(nrd_env):
    """RDAP 返回无 registration_date 字段（少见）→ None。"""
    nrd_env["result"] = None                # fake 返回 dict 值为 None
    assert rdap_nrd.is_new_registration("weird.xyz") is None
    assert rdap_nrd.stats()["skipped_error"] == 1


# ---------------------------------------------------------------------------
# 5/6. observe / intercept 模式（端到端）
# ---------------------------------------------------------------------------

def test_observe_mode_no_intercept(nrd_env, upstream):
    """observe：命中新注册只记日志，应答仍是上游正常解析 IP。"""
    domain = f"observe-{uuid.uuid4().hex[:6]}.xyz"
    nrd_env["result"] = datetime.now(timezone.utc) - timedelta(days=2)
    resp = _query(domain)
    assert resp.header.rcode == RCODE.NOERROR
    ips = [str(r.rdata) for r in resp.rr]
    assert ips == ["93.184.216.34"]         # 上游真实 IP，未拦截
    import log_writer
    log_writer._flush_once()
    logs = _read_log(domain)
    assert any(l["filter_reason"] == "nrd_observe" and l["action"] == "observe"
               and l["source_api"] == "rdap_nrd" for l in logs)


def test_intercept_mode_blocks(nrd_env, upstream):
    """intercept：命中新注册 → alert_ip 应答，日志 reason=nrd。"""
    domain = f"nrd-{uuid.uuid4().hex[:6]}.xyz"
    CONFIG.nrd_mode = "intercept"
    nrd_env["result"] = datetime.now(timezone.utc) - timedelta(days=2)
    resp = _query(domain)
    assert resp.header.rcode == RCODE.NOERROR
    ips = [str(r.rdata) for r in resp.rr]
    assert ips == [CONFIG.alert_ip]
    import log_writer
    log_writer._flush_once()
    logs = _read_log(domain)
    assert any(l["filter_reason"] == "nrd" and l["action"] == "intercept"
               for l in logs)


def test_none_verdict_passes_through(nrd_env, upstream):
    """无结论（查询失败）→ 不拦截不记 NRD 日志，走后续链路放行。"""
    domain = f"pass-{uuid.uuid4().hex[:6]}.xyz"
    nrd_env["exc"] = rdap_nrd.wi_errors.QueryError("network down")
    resp = _query(domain)
    ips = [str(r.rdata) for r in resp.rr]
    assert ips == ["93.184.216.34"]
    import log_writer
    log_writer._flush_once()
    logs = _read_log(domain)
    assert not any(l["filter_reason"].startswith("nrd") for l in logs)


def test_old_domain_no_log(nrd_env, upstream):
    """年龄超阈值 → 不拦截不记 NRD 日志（正常域名零打扰）。"""
    domain = f"old-{uuid.uuid4().hex[:6]}.xyz"
    nrd_env["result"] = datetime.now(timezone.utc) - timedelta(days=90)
    resp = _query(domain)
    assert [str(r.rdata) for r in resp.rr] == ["93.184.216.34"]
    import log_writer
    log_writer._flush_once()
    logs = _read_log(domain)
    assert not any(l["filter_reason"].startswith("nrd") for l in logs)


# ---------------------------------------------------------------------------
# 7. 开关关闭零开销
# ---------------------------------------------------------------------------

def test_disabled_zero_overhead(nrd_env, upstream):
    """nrd_enabled=False：不发查询不记日志，行为与无此层完全一致。"""
    CONFIG.nrd_enabled = False
    domain = f"off-{uuid.uuid4().hex[:6]}.xyz"
    nrd_env["result"] = datetime.now(timezone.utc) - timedelta(days=1)
    resp = _query(domain)
    assert [str(r.rdata) for r in resp.rr] == ["93.184.216.34"]
    assert nrd_env["queries"] == []         # is_new_registration 未被调用
    assert rdap_nrd.stats()["total_checked"] == 0


# ---------------------------------------------------------------------------
# 8. 配置热生效
# ---------------------------------------------------------------------------

def test_mode_hot_switch(nrd_env, upstream):
    """CONFIG 直改 mode（等价 cross_sync 热同步）：observe→intercept 立即生效。"""
    domain1 = f"hot1-{uuid.uuid4().hex[:6]}.xyz"
    domain2 = f"hot2-{uuid.uuid4().hex[:6]}.xyz"
    nrd_env["result"] = datetime.now(timezone.utc) - timedelta(days=2)
    CONFIG.nrd_mode = "intercept"
    assert [str(r.rdata) for r in _query(domain1).rr] == [CONFIG.alert_ip]
    CONFIG.nrd_mode = "observe"
    assert [str(r.rdata) for r in _query(domain2).rr] == ["93.184.216.34"]


def test_max_age_hot_adjust(nrd_env):
    """阈值热调整：90 天注册，阈值 7→120 后变命中。"""
    CONFIG.nrd_max_age_days = 7
    nrd_env["result"] = datetime.now(timezone.utc) - timedelta(days=90)
    assert rdap_nrd.is_new_registration("threshold.xyz") is False
    CONFIG.nrd_max_age_days = 120
    assert rdap_nrd.is_new_registration("threshold.xyz") is True  # 缓存内重判


# ---------------------------------------------------------------------------
# 9. stats 端点
# ---------------------------------------------------------------------------

def test_nrd_stats_endpoint(nrd_env):
    """/api/nrd/stats 返回计数快照。"""
    from fastapi.testclient import TestClient
    from app.main import app
    nrd_env["result"] = datetime.now(timezone.utc) - timedelta(days=3)
    rdap_nrd.is_new_registration("stats-target.xyz")
    with TestClient(app) as client:        # 上下文管理器触发 startup seed
        r = client.post("/api/auth/login",
                        json={"username": "admin",
                              "password": CONFIG.admin_initial_password})
        token = r.json()["data"]["token"]
        r = client.get("/api/nrd/stats",
                       headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["rdap_queries"] == 1
        assert data["hits_new"] == 1


# ---------------------------------------------------------------------------
# 10. DB 迁移
# ---------------------------------------------------------------------------

def test_nrd_cache_table_exists():
    """nrd_cache 表已建（schema.sql 新库 / _migrate 旧库均覆盖）。"""
    with db_cursor() as cur:
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='nrd_cache'")
        assert cur.fetchone() is not None
        # 列结构
        cols = {r["name"] for r in cur.execute(
            "PRAGMA table_info(nrd_cache)").fetchall()}
        assert cols == {"domain", "registered_at", "queried_at"}


def test_migrate_adds_table_to_legacy_db(tmp_path, monkeypatch):
    """旧库（无 nrd_cache）经 _migrate 自动补建。"""
    import sqlite3
    legacy = tmp_path / "legacy.db"
    conn = sqlite3.connect(legacy)
    conn.execute("CREATE TABLE system_config (key VARCHAR PRIMARY KEY, "
                 "value VARCHAR NOT NULL, updated_at DATETIME)")
    conn.commit()
    conn.close()

    monkeypatch.setattr(CONFIG, "database", str(legacy))
    # 复位线程本地连接（新库路径需重连）
    import app.db as db_mod
    monkeypatch.setattr(db_mod._local, "conn", None)
    try:
        db_mod.get_conn()                    # 触发 init_schema + _migrate
        with db_cursor() as cur:
            cur.execute("SELECT name FROM sqlite_master "
                        "WHERE type='table' AND name='nrd_cache'")
            assert cur.fetchone() is not None
    finally:
        # 还原线程连接（后续测试用回测试库）
        monkeypatch.setattr(db_mod._local, "conn", None)
        db_mod.get_conn()
