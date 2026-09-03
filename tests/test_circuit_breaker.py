"""熔断与降级测试 —— 10 万终端前置开发项 2。

覆盖：
  - 源级熔断：连续失败达阈值 → open（跳过调用）→ 冷却后 half-open 探测
    → 成功关闭 / 失败重熔断
  - 路径级降级：intercept 模式维持 fail-safe 拦截；degrade 模式连续
    fail-safe 达阈值开降级窗口（在线检测跳过放行）；窗口结束恢复；
    有结论提前结束窗口
  - 缓存联动：降级窗口内缓存恶意结论仍生效（不放过恶意域名）
  - 手动复位 reset_all
  - 状态接口数据结构
"""

import pytest
from dnslib import DNSRecord

import circuit_breaker
import domain_cache
from config import CONFIG
from detectors import process_query, query_threatintel_domain
from app.db import db_cursor


@pytest.fixture(autouse=True)
def clean_state():
    """每个测试前后复位熔断器/降级状态与缓存。"""
    circuit_breaker.reset_all()
    domain_cache.clear()
    domain_cache.STATS["hits"] = 0
    domain_cache.STATS["misses"] = 0
    yield
    circuit_breaker.reset_all()
    domain_cache.clear()
    domain_cache.STATS["hits"] = 0
    domain_cache.STATS["misses"] = 0


@pytest.fixture
def cb_config():
    """快熔断参数（阈值 3 / 冷却 60s），测试后还原。"""
    saved = {k: getattr(CONFIG, k) for k in (
        "cb_failure_threshold", "cb_open_timeout_s",
        "degrade_threshold", "degrade_window_s", "failsafe_mode")}
    CONFIG.cb_failure_threshold = 3
    CONFIG.cb_open_timeout_s = 60
    CONFIG.degrade_threshold = 3
    CONFIG.degrade_window_s = 300
    CONFIG.failsafe_mode = "intercept"
    yield CONFIG
    for k, v in saved.items():
        setattr(CONFIG, k, v)


def _make_adapter_class(adapters_mod, name, result_fn):
    """构造行为可定制的假适配器类。"""
    class FakeAdapter(adapters_mod.ThreatIntelAdapter):
        _name = name
        supports_domain = True
        supports_ip = False

        def query_domain(self, domain):
            return result_fn(domain)

        def query_ip(self, ip):
            return None

    FakeAdapter.name = name
    return FakeAdapter


# ---------------- 源级熔断 ----------------

def test_breaker_opens_after_threshold(cb_config, monkeypatch):
    """连续失败达阈值 → open，后续查询跳过该源（不再调用）。"""
    import detectors as detectors_mod
    import adapters as adapters_mod
    from adapters import ThreatResult

    calls = {"n": 0}

    def always_fail(domain):
        calls["n"] += 1
        return None                          # 无结论（超时/故障）

    cls = _make_adapter_class(adapters_mod, "flaky", always_fail)
    monkeypatch.setattr(detectors_mod, "get_enabled_adapters", lambda: [cls()])

    for i in range(5):
        query_threatintel_domain("a.test")   # 前 3 次真实调用，后 2 次熔断跳过
    assert calls["n"] == 3                   # 第 4、5 次未调该源
    assert circuit_breaker.source_states()["flaky"]["state"] == "open"


def test_breaker_halfopen_recovery(cb_config, monkeypatch):
    """熔断 → 冷却到期 → half-open 放行一次探测 → 成功则关闭。"""
    import detectors as detectors_mod
    import adapters as adapters_mod
    from adapters import ThreatResult

    calls = {"n": 0}

    def flaky_then_ok(domain):
        calls["n"] += 1
        if calls["n"] <= 3:
            return None                      # 前 3 次失败 → 熔断
        return ThreatResult(is_malicious=False, source="flaky")

    cls = _make_adapter_class(adapters_mod, "flaky", flaky_then_ok)
    monkeypatch.setattr(detectors_mod, "get_enabled_adapters", lambda: [cls()])

    for _ in range(3):
        query_threatintel_domain("a.test")
    assert circuit_breaker.source_states()["flaky"]["state"] == "open"

    # 冷却到期（把 opened_at 拨到过去）
    with circuit_breaker._LOCK:
        circuit_breaker._BREAKERS["flaky"]["opened_at"] -= 61

    r = query_threatintel_domain("b.test")   # half-open 探测：调用 + 成功
    assert calls["n"] == 4
    assert circuit_breaker.source_states()["flaky"]["state"] == "closed"
    assert r[0] is False                     # 有结论（未命中）


def test_breaker_halfopen_refail(cb_config, monkeypatch):
    """半开探测失败 → 立即重新熔断。"""
    import detectors as detectors_mod
    import adapters as adapters_mod

    calls = {"n": 0}

    def always_fail(domain):
        calls["n"] += 1
        return None

    cls = _make_adapter_class(adapters_mod, "flaky", always_fail)
    monkeypatch.setattr(detectors_mod, "get_enabled_adapters", lambda: [cls()])

    for _ in range(3):
        query_threatintel_domain("a.test")   # 熔断
    with circuit_breaker._LOCK:
        circuit_breaker._BREAKERS["flaky"]["opened_at"] -= 61

    query_threatintel_domain("b.test")       # half-open 探测失败
    assert calls["n"] == 4
    st = circuit_breaker.source_states()["flaky"]
    # 重新 open（source_states 展示口径：未到冷却显示 open）
    assert st["state"] == "open"


# ---------------- fail-safe 模式 ----------------

def test_failsafe_intercept_default(cb_config, monkeypatch):
    """intercept 模式（默认）：全源无结论 → 拦截，且不触发降级窗口。"""
    import detectors as detectors_mod
    import adapters as adapters_mod

    def always_fail(domain):
        return None

    cls = _make_adapter_class(adapters_mod, "dead", always_fail)
    monkeypatch.setattr(detectors_mod, "get_enabled_adapters", lambda: [cls()])

    for _ in range(5):
        malicious, reason = query_threatintel_domain("x.test")
        assert malicious is True             # fail-safe 默认拦截
    assert circuit_breaker.is_degraded() is False   # intercept 不降级
    assert domain_cache.stats()["size"] == 0        # 不落缓存


def test_failsafe_degrade_opens_window(cb_config, monkeypatch):
    """degrade 模式：连续 fail-safe 达阈值 → 降级窗口，在线检测跳过放行。"""
    import detectors as detectors_mod
    import adapters as adapters_mod

    CONFIG.failsafe_mode = "degrade"

    calls = {"n": 0}

    def always_fail(domain):
        calls["n"] += 1
        return None

    cls = _make_adapter_class(adapters_mod, "dead", always_fail)
    monkeypatch.setattr(detectors_mod, "get_enabled_adapters", lambda: [cls()])

    # 前 3 次（=阈值）：fail-safe 降级放行
    for i in range(3):
        malicious, reason = query_threatintel_domain("x.test")
        assert malicious is False
        assert reason == "degraded:failsafe"
    # 第 3 次已触发降级窗口
    assert circuit_breaker.is_degraded() is True
    assert calls["n"] == 3

    # 窗口内：直接跳过（零适配器调用）
    malicious, reason = query_threatintel_domain("y.test")
    assert malicious is False
    assert reason == "degraded"
    assert calls["n"] == 3                   # 无新增调用
    assert domain_cache.stats()["size"] == 0  # 降级结论不落缓存


def test_degrade_window_expires(cb_config, monkeypatch):
    """降级窗口到期自动恢复，恢复后重新计数。"""
    import detectors as detectors_mod
    import adapters as adapters_mod

    CONFIG.failsafe_mode = "degrade"

    def always_fail(domain):
        return None

    cls = _make_adapter_class(adapters_mod, "dead", always_fail)
    monkeypatch.setattr(detectors_mod, "get_enabled_adapters", lambda: [cls()])

    for _ in range(3):
        query_threatintel_domain("x.test")
    assert circuit_breaker.is_degraded() is True

    # 快进：窗口截止时刻拨到过去
    with circuit_breaker._LOCK:
        circuit_breaker._DEGRADE["degraded_until"] = 0.0

    assert circuit_breaker.is_degraded() is False
    # 恢复后又有一次 fail-safe（计数重新累计，未到阈值不触发新窗口）
    malicious, _ = query_threatintel_domain("z.test")
    assert malicious is False                # 单次 fail-safe → degrade 放行
    assert circuit_breaker.is_degraded() is False


def test_degrade_ends_early_on_verdict(cb_config, monkeypatch):
    """降级窗口内出现有结论查询（缓存 miss 后源恢复）→ 提前结束窗口。"""
    import detectors as detectors_mod
    import adapters as adapters_mod
    from adapters import ThreatResult

    CONFIG.failsafe_mode = "degrade"
    calls = {"n": 0}

    def fail_then_ok(domain):
        calls["n"] += 1
        if calls["n"] <= 3:
            return None
        return ThreatResult(is_malicious=False, source="flaky")

    cls = _make_adapter_class(adapters_mod, "flaky", fail_then_ok)
    monkeypatch.setattr(detectors_mod, "get_enabled_adapters", lambda: [cls()])

    for _ in range(3):
        query_threatintel_domain("a.test")   # 3 次 fail-safe → 降级窗口
    assert circuit_breaker.is_degraded() is True

    # 窗口内查新域名 → is_degraded 直接跳过（源未被探测）。这里验证
    # record_verdict 的提前恢复路径：直接模拟窗口内出现有结论
    circuit_breaker.record_verdict()
    assert circuit_breaker.is_degraded() is False


# ---------------- 缓存联动 ----------------

def test_degrade_keeps_cached_malicious(cb_config, monkeypatch):
    """降级窗口内，缓存中的恶意结论仍生效（不放过恶意域名）。"""
    import detectors as detectors_mod
    import adapters as adapters_mod
    from adapters import ThreatResult

    CONFIG.failsafe_mode = "degrade"
    # 先在源健康期写入恶意结论缓存
    def malicious_fn(domain):
        return ThreatResult(is_malicious=True, source="good")

    cls = _make_adapter_class(adapters_mod, "good", malicious_fn)
    monkeypatch.setattr(detectors_mod, "get_enabled_adapters", lambda: [cls()])
    m1, r1 = query_threatintel_domain("bad.test")
    assert m1 is True
    assert domain_cache.get("bad.test") is not None

    # 进入降级窗口（直接模拟）
    with circuit_breaker._LOCK:
        circuit_breaker._DEGRADE["degraded_until"] = circuit_breaker._LOCK and \
            __import__("time").monotonic() + 60

    m2, r2 = query_threatintel_domain("bad.test")
    assert m2 is True                        # 缓存恶意结论命中，仍拦截
    assert r2 == r1


# ---------------- 复位 ----------------

def test_reset_all(cb_config):
    with circuit_breaker._LOCK:
        circuit_breaker._BREAKERS["x"] = {
            "state": "open", "failures": 5, "opened_at": 0.0}
        circuit_breaker._DEGRADE.update(
            consecutive_failsafes=9, degraded_until=1e18, degrade_count=7)
    circuit_breaker.reset_all()
    assert circuit_breaker.source_states() == {}
    assert circuit_breaker.is_degraded() is False
    assert circuit_breaker.degrade_state()["consecutive_failsafes"] == 0


def test_degrade_state_shape(cb_config):
    st = circuit_breaker.degrade_state()
    assert set(st) == {"mode", "degraded", "degrade_remaining_s",
                       "consecutive_failsafes", "degrade_count"}
    assert st["mode"] in ("intercept", "degrade")


# ===========================================================================
# 上游解析熔断（Task #159，生产事故 2026-09-03 加固）
#
# 事故根因：出站间歇性超时 + 检测线程全部挂在 3s send() 等待 →
# executor 主池（6 worker）耗尽 → 全网瘫。本节验证针对性防护：
#   - 连续失败达阈值 → 熔断开窗，窗口内 query_upstream_reply 直接
#     SERVFAIL（fast-fail，0ms，不占用出站等待）
#   - 窗口到期半开探测：成功关闭 / 失败重开
#   - 任何合法应答（含 NXDOMAIN）都算成功
#   - 状态接口含上游快照；reset_all 联动复位
# ===========================================================================

@pytest.fixture
def upstream_cfg():
    """快上游熔断参数（阈值 3 / 窗口 10s），测试后还原。"""
    saved = {k: getattr(CONFIG, k) for k in (
        "upstream_failure_threshold", "upstream_open_timeout_s",
        "upstream_timeout_s")}
    CONFIG.upstream_failure_threshold = 3
    CONFIG.upstream_open_timeout_s = 10
    CONFIG.upstream_timeout_s = 3
    yield CONFIG
    for k, v in saved.items():
        setattr(CONFIG, k, v)


def _servfail_on_send(monkeypatch, calls=None):
    """让 DNSRecord.send 全部超时（模拟出站故障），可记录调用次数。"""
    def _fail(self, *a, **kw):
        if calls is not None:
            calls.append(1)
        raise TimeoutError("模拟出站超时")
    monkeypatch.setattr(DNSRecord, "send", _fail)


def test_upstream_breaker_opens_after_threshold(upstream_cfg, monkeypatch):
    """连续失败达阈值 → open：后续请求不再出站，直接 SERVFAIL。"""
    from dnslib import RCODE
    import detectors
    calls = []
    _servfail_on_send(monkeypatch, calls)

    q = DNSRecord.question("x.test", "A")
    # 阈值 3：前 3 次真实出站（全超时），第 4 次起 fast-fail
    for _ in range(3):
        detectors.query_upstream_reply(q)
    assert circuit_breaker.upstream_state()["state"] == "open"
    assert calls == [1, 1, 1]                 # 3 次真实出站

    r4 = detectors.query_upstream_reply(q)
    assert r4.header.rcode == RCODE.SERVFAIL   # fast-fail
    assert len(calls) == 3                     # 第 4 次没有出站！
    st = circuit_breaker.upstream_state()
    assert st["open_count"] == 1 and st["fast_fails"] >= 1


def test_upstream_breaker_recovers_on_success(upstream_cfg, monkeypatch):
    """熔断到期半开探测成功 → 关闭恢复（任何合法应答算成功，含 NXDOMAIN）。"""
    from dnslib import RCODE
    import detectors
    _servfail_on_send(monkeypatch)
    q = DNSRecord.question("y.test", "A")
    for _ in range(3):
        detectors.query_upstream_reply(q)      # 熔断

    # 时间快进 11s：open → half-open（下一次放行探测）
    with circuit_breaker._LOCK:
        circuit_breaker._UPSTREAM["opened_at"] -= 11

    def _ok(self, *a, **kw):
        return q.reply().pack()
    monkeypatch.setattr(DNSRecord, "send", _ok)
    r = detectors.query_upstream_reply(q)
    assert r.header.rcode == RCODE.NOERROR      # 真实应答
    assert circuit_breaker.upstream_state()["state"] == "closed"


def test_upstream_half_open_probe_failure_reopens(upstream_cfg, monkeypatch):
    """半开探测失败 → 立即重新熔断（不等阈值重新累计）。"""
    import detectors
    _servfail_on_send(monkeypatch)
    q = DNSRecord.question("z.test", "A")
    for _ in range(3):
        detectors.query_upstream_reply(q)      # 熔断
    with circuit_breaker._LOCK:
        circuit_breaker._UPSTREAM["opened_at"] -= 11   # 进入 half-open

    detectors.query_upstream_reply(q)          # 探测（仍超时）
    st = circuit_breaker.upstream_state()
    assert st["state"] == "open"               # 立即重开


def test_upstream_disabled_threshold_zero(upstream_cfg, monkeypatch):
    """阈值 0 = 禁用熔断：失败再多也不 fast-fail。"""
    from dnslib import RCODE
    import detectors
    CONFIG.upstream_failure_threshold = 0
    calls = []
    _servfail_on_send(monkeypatch, calls)
    q = DNSRecord.question("w.test", "A")
    for _ in range(10):
        r = detectors.query_upstream_reply(q)
        assert r.header.rcode == RCODE.SERVFAIL
    assert len(calls) == 10                    # 每次都真实出站
    assert circuit_breaker.upstream_state()["state"] == "closed"


def test_upstream_state_shape_and_reset(upstream_cfg):
    st = circuit_breaker.upstream_state()
    assert set(st) == {"state", "failures", "open_count", "fast_fails"}
    assert st["state"] in ("closed", "open", "half-open")
    with circuit_breaker._LOCK:
        circuit_breaker._UPSTREAM.update(
            state="open", failures=5, opened_at=0.0, open_count=2, fast_fails=9)
    circuit_breaker.reset_all()
    assert circuit_breaker.upstream_state() == {
        "state": "closed", "failures": 0, "open_count": 0, "fast_fails": 0}


def test_upstream_breaker_stats_endpoint(upstream_cfg):
    """/circuit-breaker/stats 含 upstream 快照（Task #159 接口口径）。"""
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        r = c.post("/api/auth/login", json={
            "username": "admin", "password": CONFIG.admin_initial_password})
        token = r.json()["data"]["token"]
        r = c.get("/api/circuit-breaker/stats",
                  headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        data = r.json()["data"]
        assert "upstream" in data
        assert set(data["upstream"]) == {
            "state", "failures", "open_count", "fast_fails"}
