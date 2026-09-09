"""离线 NRD 检测层测试（迭代 41：hagezi/nrd 大名单承载）。

覆盖：
  1. 源元数据：hagezi_nrd 在 SOURCES（URL/format/周期/大小上限）+ 镜像规则；
  2. 下载完整性：Content-Length 不足抛 IOError（触发上层镜像降级）；
  3. 导入截断防护：文件头 "# Number of entries" 声明与实际解析偏差
     超 1% 拒绝入库（整源替换防半份数据）；无声明头不受影响；
  4. observe 模式：命中记 nrd_offline_observe 日志不拦截（上游正常 IP）；
  5. intercept 模式：命中拦截（alert_ip 应答，reason=nrd_offline）；
  6. 开关关闭：NRD 源命中视同未命中（不拦截不记日志，普通源照旧拦截）；
  7. 普通离线源不受 NRD 语义影响（threat_list:<key> 照旧拦截）；
  8. 白名单优先级高于离线 NRD 层（误报兜底）；
  9. 配置热切换（observe→intercept）+ nrd_offline_mode 非法值 400；
 10. reasons 端点含新 fixed 项 + reason 筛选排除包含近邻键
     （筛 nrd_offline 不混入 nrd_offline_observe）。

网络隔离：导入用本地构造文本（模拟 hagezi/nrd 文件头+条目），
端到端走 FakeUpstream 线程 UDP 上游（test_nrd 同款），不依赖公网。

运行：cd platform && python -m pytest ../tests/test_nrd_offline.py -v
"""

import uuid

import pytest
from dnslib import DNSRecord, QTYPE, RR, A, RCODE

from config import CONFIG
from app import threat_list
from app.db import db_cursor
from detectors import process_query


# ---------------------------------------------------------------------------
# 测试环境（沿袭 test_nrd 的隔离模式：filter_list 快照清理 + 在线源禁用）
# ---------------------------------------------------------------------------

@pytest.fixture
def nrd_offline_env(monkeypatch):
    """离线 NRD 测试环境：清跨测试残留、导入 NRD 测试名单、还原配置。

    - filter_list 快照后清空（防 test_e2e 遗留黑名单 CIDR 命中
      FakeUpstream 应答 IP → IP 后置误拦），结束原样恢复；
    - threatintel_api 全禁用（防 testcenter 遗留 example 恒无结论 →
      fail-safe 误拦）；
    - threat_list 清 hagezi_nrd + 白名单域名行（跨测试残留防护），
    - CONFIG 四键快照还原。
    """
    state = {"domains": []}

    with db_cursor() as cur:
        cur.execute("SELECT * FROM filter_list")
        _saved_filter_list = [tuple(r) for r in cur.fetchall()]
        cur.execute("DELETE FROM filter_list")
        cur.execute("UPDATE threatintel_api SET enabled=0")
        cur.execute("DELETE FROM threat_list WHERE source='hagezi_nrd'")
        cur.execute("DELETE FROM filter_list WHERE list_type='whitelist'")

    saved = {k: getattr(CONFIG, k) for k in
             ("nrd_offline_enabled", "nrd_offline_mode",
              "nrd_enabled", "detection_enabled")}
    CONFIG.nrd_enabled = False          # 在线 RDAP 层关闭（单测离线层）
    CONFIG.detection_enabled = True
    yield state
    for k, v in saved.items():
        setattr(CONFIG, k, v)
    threat_list.delete_source("hagezi_nrd")
    with db_cursor() as cur:
        cur.execute("DELETE FROM filter_log WHERE domain LIKE 'it41-%'")
        cur.execute("DELETE FROM filter_list WHERE list_type='whitelist'")
    # 恢复 filter_list 快照（INSERT OR REPLACE 按原主键写回）
    if _saved_filter_list:
        with db_cursor() as cur:
            placeholders = ",".join("?" * len(_saved_filter_list[0]))
            cur.executemany(
                f"INSERT OR REPLACE INTO filter_list VALUES ({placeholders})",
                _saved_filter_list)


def _seed_nrd(state, domains):
    """导入 NRD 测试名单（带 hagezi/nrd 真实文件头形态）。"""
    state["domains"] = list(domains)
    header = (
        "# Title: Newly Registered Domains\n"
        "# Last modified: 09 Sep 2026 06:02 UTC\n"
        "# Number of entries: 3284910\n"
        "# Expires: 8 hours\n"
    )
    # 头声明数与实际条数偏差大→校验会拒；测试名单头声明数取真实条数
    header = header.replace("3284910", str(len(domains)))
    text = header + "\n".join(domains) + "\n"
    threat_list.import_source("hagezi_nrd", text, fmt="plain")


def _query(domain: str) -> DNSRecord:
    return process_query(DNSRecord.question(domain, "A"),
                         client_ip="192.168.1.100")


def _read_log(domain: str) -> list[dict]:
    with db_cursor() as cur:
        cur.execute(
            "SELECT filter_reason, action, source_api FROM filter_log "
            "WHERE domain=? ORDER BY id DESC LIMIT 5", (domain,))
        return [dict(r) for r in cur.fetchall()]


class FakeUpstream:
    """线程 UDP 上游（test_nrd 同款）：A → 93.184.216.34。"""

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


# ---------------------------------------------------------------------------
# 1. 源元数据与镜像
# ---------------------------------------------------------------------------

def test_nrd_source_metadata():
    """hagezi_nrd 源定义：URL 指向 hagezi/nrd 仓库、plain 格式、
    24h 周期、128MB 上限、且在 NRD_SOURCE_KEYS 集合（检测分流依据）。"""
    meta = {s["key"]: s for s in threat_list.SOURCES}
    assert "hagezi_nrd" in meta
    s = meta["hagezi_nrd"]
    assert s["url"] == ("https://raw.githubusercontent.com/hagezi/nrd/"
                        "main/domains/nrd7.txt")
    assert s["format"] == "plain"
    assert s["update_interval_s"] == 24 * 3600
    assert s["max_bytes"] == 128 * 1024 * 1024
    assert "hagezi_nrd" in threat_list.NRD_SOURCE_KEYS


def test_nrd_mirror_rule():
    """hagezi/nrd 仓库 raw → jsDelivr 镜像映射（主地址不可达时降级）。"""
    assert threat_list._mirror_of(
        "https://raw.githubusercontent.com/hagezi/nrd/main/domains/nrd7.txt"
    ) == "https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/domains/nrd7.txt"


# ---------------------------------------------------------------------------
# 2. 下载完整性校验（Content-Length）
# ---------------------------------------------------------------------------

def test_download_truncated_raises(monkeypatch):
    """流提前结束（收到 < Content-Length）→ IOError，交给上层镜像降级。"""

    class FakeResp:
        headers = {"content-length": "1000"}

        def raise_for_status(self):
            pass

        def iter_bytes(self, _size):
            yield b"a.com\n" * 10          # 仅 60 字节 < 声明 1000

    class FakeStream:
        def __enter__(self):
            return FakeResp()

        def __exit__(self, *a):
            return False

    import app.http_client as hc
    monkeypatch.setattr(hc, "stream", lambda *a, **kw: FakeStream())
    with pytest.raises(IOError, match="下载不完整"):
        threat_list._download_once("https://example.com/list.txt",
                                   max_bytes=10 * 1024 * 1024, timeout_s=30)


def test_download_complete_no_error(monkeypatch):
    """收满 Content-Length → 正常返回（校验不误伤健康下载）。"""

    class FakeResp:
        headers = {"content-length": "12"}

        def raise_for_status(self):
            pass

        def iter_bytes(self, _size):
            yield b"a.com\nb.com\n"        # 恰 12 字节

    class FakeStream:
        def __enter__(self):
            return FakeResp()

        def __exit__(self, *a):
            return False

    import app.http_client as hc
    monkeypatch.setattr(hc, "stream", lambda *a, **kw: FakeStream())
    text = threat_list._download_once("https://example.com/list.txt",
                                      max_bytes=10 * 1024 * 1024, timeout_s=30)
    assert text == "a.com\nb.com\n"


def test_download_no_content_length_passes(monkeypatch):
    """chunked 传输无 Content-Length（expected=0）→ 跳过校验
    （截断防护交给导入侧文件头条数校验兜底）。"""

    class FakeResp:
        headers = {}

        def raise_for_status(self):
            pass

        def iter_bytes(self, _size):
            yield b"a.com\n"

    class FakeStream:
        def __enter__(self):
            return FakeResp()

        def __exit__(self, *a):
            return False

    import app.http_client as hc
    monkeypatch.setattr(hc, "stream", lambda *a, **kw: FakeStream())
    assert threat_list._download_once(
        "https://example.com/list.txt",
        max_bytes=10 * 1024 * 1024, timeout_s=30) == "a.com\n"


def test_download_truncated_triggers_mirror(monkeypatch):
    """主地址截断 → download() 捕获异常降级镜像重试（集成链路）。"""
    calls = []

    def fake_once(url, max_bytes, timeout_s, progress=None):
        calls.append(url)
        if len(calls) == 1:
            raise IOError("下载不完整：收到 100 / 声明 1000 字节")
        return "a.com\n"

    monkeypatch.setattr(threat_list, "_download_once", fake_once)
    text = threat_list.download(
        "https://raw.githubusercontent.com/hagezi/nrd/main/domains/nrd7.txt")
    assert text == "a.com\n"
    assert len(calls) == 2
    assert "cdn.jsdelivr.net" in calls[1]   # 已降级镜像


# ---------------------------------------------------------------------------
# 3. 导入截断防护（文件头条数校验）
# ---------------------------------------------------------------------------

def test_declared_entry_count_parses():
    """文件头声明数解析：hagezi/nrd 真实形态。"""
    text = ("# Title: Newly Registered Domains\n"
            "# Last modified: 09 Sep 2026 06:02 UTC\n"
            "# Number of entries: 3284910\n"
            "# Expires: 8 hours\n"
            "example.com\n")
    assert threat_list.declared_entry_count(text) == 3284910
    assert threat_list.declared_entry_count("a.com\nb.com\n") is None


def test_import_truncated_rejected(nrd_offline_env):
    """声明 100 条实际解析 50 条（截断一半）→ ValueError 拒绝入库，
    且旧数据不被清掉（整源替换 DELETE 未执行）。"""
    _seed_nrd(nrd_offline_env, ["it41-old.example"])
    # 构造截断文件：头声明 100，正文只有 1 条有效（偏差 99%）
    text = ("# Number of entries: 100\n"
            "it41-truncated.example\n")
    with pytest.raises(ValueError, match="疑似截断"):
        threat_list.import_source("hagezi_nrd", text)
    # 旧数据完好
    assert threat_list.find_domain("it41-old.example") is not None


def test_import_within_tolerance_passes(nrd_offline_env):
    """声明 100 条实际 100 条 → 正常入库（校验不误伤）。"""
    domains = [f"it41-t{i:03d}.example" for i in range(100)]
    text = f"# Number of entries: 100\n" + "\n".join(domains) + "\n"
    n = threat_list.import_source("hagezi_nrd", text)
    assert n == 100
    assert threat_list.find_domain("it41-t000.example") is not None


def test_import_small_drift_within_1pct_passes(nrd_offline_env):
    """上游同日微调（偏差 ≤1%）→ 放行：声明 200 实际 199（0.5%）。"""
    domains = [f"it41-d{i:03d}.example" for i in range(199)]
    text = f"# Number of entries: 200\n" + "\n".join(domains) + "\n"
    n = threat_list.import_source("hagezi_nrd", text)
    assert n == 199


def test_import_no_header_not_affected(nrd_offline_env):
    """普通列表（无声明头）不受校验影响：其他源照常导入。"""
    n = threat_list.import_source("hagezi_ti", "plain-a.example\n")
    try:
        assert n == 1
        assert threat_list.find_domain("plain-a.example") == (
            "hagezi_ti", "plain-a.example")
    finally:
        threat_list.delete_source("hagezi_ti")


# ---------------------------------------------------------------------------
# 4/5. observe / intercept 语义（端到端）
# ---------------------------------------------------------------------------

def test_observe_mode_no_intercept(nrd_offline_env, upstream):
    """observe：NRD 命中只记 nrd_offline_observe 日志，应答仍是上游 IP。"""
    domain = f"it41-observe-{uuid.uuid4().hex[:6]}.xyz"
    _seed_nrd(nrd_offline_env, [domain])
    CONFIG.nrd_offline_enabled = True
    CONFIG.nrd_offline_mode = "observe"
    resp = _query(domain)
    assert resp.header.rcode == RCODE.NOERROR
    assert [str(r.rdata) for r in resp.rr] == ["93.184.216.34"]  # 未拦截
    import log_writer
    log_writer._flush_once()
    logs = _read_log(domain)
    assert any(l["filter_reason"] == "nrd_offline_observe"
               and l["action"] == "observe"
               and l["source_api"] == "hagezi_nrd" for l in logs)


def test_intercept_mode_blocks(nrd_offline_env, upstream):
    """intercept：NRD 命中 → alert_ip 应答，reason=nrd_offline。"""
    domain = f"it41-block-{uuid.uuid4().hex[:6]}.xyz"
    _seed_nrd(nrd_offline_env, [domain])
    CONFIG.nrd_offline_enabled = True
    CONFIG.nrd_offline_mode = "intercept"
    resp = _query(domain)
    assert resp.header.rcode == RCODE.NOERROR
    assert [str(r.rdata) for r in resp.rr] == [CONFIG.alert_ip]
    import log_writer
    log_writer._flush_once()
    logs = _read_log(domain)
    assert any(l["filter_reason"] == "nrd_offline"
               and l["action"] == "intercept"
               and l["source_api"] == "hagezi_nrd" for l in logs)


def test_subdomain_hits_parent_entry(nrd_offline_env, upstream):
    """逐级父域匹配：列表含主域，子域查询同样命中 NRD 层（与
    threat_list 既有匹配语义一致）。"""
    _seed_nrd(nrd_offline_env, ["it41-parent.example"])
    CONFIG.nrd_offline_enabled = True
    CONFIG.nrd_offline_mode = "intercept"
    resp = _query("it41-deep.sub.it41-parent.example")
    assert [str(r.rdata) for r in resp.rr] == [CONFIG.alert_ip]


def test_unlisted_domain_passes(nrd_offline_env, upstream):
    """名单外域名：不记 NRD 日志、正常放行（零打扰）。"""
    domain = f"it41-clean-{uuid.uuid4().hex[:6]}.com"
    _seed_nrd(nrd_offline_env, ["it41-other.example"])
    CONFIG.nrd_offline_enabled = True
    CONFIG.nrd_offline_mode = "intercept"
    resp = _query(domain)
    assert [str(r.rdata) for r in resp.rr] == ["93.184.216.34"]
    import log_writer
    log_writer._flush_once()
    assert not any(l["filter_reason"].startswith("nrd")
                   for l in _read_log(domain))


# ---------------------------------------------------------------------------
# 6. 开关关闭零影响
# ---------------------------------------------------------------------------

def test_disabled_treated_as_miss(nrd_offline_env, upstream):
    """nrd_offline_enabled=False：NRD 命中视同未命中——不拦截不记日志。"""
    domain = f"it41-off-{uuid.uuid4().hex[:6]}.xyz"
    _seed_nrd(nrd_offline_env, [domain])
    CONFIG.nrd_offline_enabled = False
    resp = _query(domain)
    assert [str(r.rdata) for r in resp.rr] == ["93.184.216.34"]
    import log_writer
    log_writer._flush_once()
    assert not any(l["filter_reason"].startswith("nrd")
                   for l in _read_log(domain))


def test_disabled_but_normal_source_still_blocks(nrd_offline_env, upstream):
    """开关关闭只豁免 NRD 源：普通离线源（hagezi_ti）照旧拦截。"""
    domain = f"it41-normal-{uuid.uuid4().hex[:6]}.xyz"
    _seed_nrd(nrd_offline_env, ["it41-nrd-only.example"])
    threat_list.import_source("hagezi_ti", domain + "\n")
    CONFIG.nrd_offline_enabled = False      # NRD 层关闭
    resp = _query(domain)
    assert [str(r.rdata) for r in resp.rr] == [CONFIG.alert_ip]
    import log_writer
    log_writer._flush_once()
    logs = _read_log(domain)
    assert any(l["filter_reason"] == "threat_list:hagezi_ti"
               and l["action"] == "intercept" for l in logs)


# ---------------------------------------------------------------------------
# 7. 普通源不受 NRD 语义影响（开关开启时）
# ---------------------------------------------------------------------------

def test_normal_source_unaffected_when_nrd_on(nrd_offline_env, upstream):
    """NRD 层开启（intercept）时，普通源命中仍走 threat_list:<key> 拦截。"""
    domain = f"it41-mixed-{uuid.uuid4().hex[:6]}.xyz"
    _seed_nrd(nrd_offline_env, ["it41-a.example"])
    threat_list.import_source("stevenblack", domain + "\n")
    CONFIG.nrd_offline_enabled = True
    CONFIG.nrd_offline_mode = "observe"
    resp = _query(domain)
    assert [str(r.rdata) for r in resp.rr] == [CONFIG.alert_ip]
    import log_writer
    log_writer._flush_once()
    logs = _read_log(domain)
    assert any(l["filter_reason"] == "threat_list:stevenblack"
               and l["action"] == "intercept" for l in logs)
    threat_list.delete_source("stevenblack")


# ---------------------------------------------------------------------------
# 8. 白名单优先
# ---------------------------------------------------------------------------

def test_whitelist_beats_nrd(nrd_offline_env, upstream):
    """白名单域名命中 NRD 名单 → 白名单优先直接放行（误报兜底）。"""
    domain = f"it41-wl-{uuid.uuid4().hex[:6]}.xyz"
    _seed_nrd(nrd_offline_env, [domain])
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO filter_list (list_type, target, value, remark, enabled) "
            "VALUES ('whitelist', 'domain', ?, 'it41 白名单优先测试', 1)",
            (domain,))
    from app.db import invalidate_list_cache
    invalidate_list_cache()
    CONFIG.nrd_offline_enabled = True
    CONFIG.nrd_offline_mode = "intercept"
    try:
        resp = _query(domain)
        assert [str(r.rdata) for r in resp.rr] == ["93.184.216.34"]
    finally:
        with db_cursor() as cur:
            cur.execute("DELETE FROM filter_list WHERE value=?", (domain,))
        invalidate_list_cache()


# ---------------------------------------------------------------------------
# 9. 配置热切换 + API 校验
# ---------------------------------------------------------------------------

def test_mode_hot_switch(nrd_offline_env, upstream):
    """CONFIG 直改（等价 cross_sync 热同步）：observe→intercept 立即生效。"""
    d1 = f"it41-hot1-{uuid.uuid4().hex[:6]}.xyz"
    d2 = f"it41-hot2-{uuid.uuid4().hex[:6]}.xyz"
    _seed_nrd(nrd_offline_env, [d1, d2])
    CONFIG.nrd_offline_enabled = True
    CONFIG.nrd_offline_mode = "intercept"
    assert [str(r.rdata) for r in _query(d1).rr] == [CONFIG.alert_ip]
    CONFIG.nrd_offline_mode = "observe"
    assert [str(r.rdata) for r in _query(d2).rr] == ["93.184.216.34"]


def test_config_api_validates_and_applies(client, token):
    """/api/config：nrd_offline_mode 非法值 400；合法值写入+热生效。"""
    h = {"Authorization": f"Bearer {token}"}
    r = client.put("/api/config", headers=h,
                   json={"nrd_offline_mode": "block"})
    assert r.status_code == 400
    r = client.put("/api/config", headers=h,
                   json={"nrd_offline_enabled": True,
                         "nrd_offline_mode": "observe"})
    assert r.status_code == 200
    assert CONFIG.nrd_offline_enabled is True
    assert CONFIG.nrd_offline_mode == "observe"
    # 还原（不污染其他测试）
    client.put("/api/config", headers=h,
               json={"nrd_offline_enabled": False,
                     "nrd_offline_mode": "observe"})


def test_config_api_rejects_bad_bool_type(client, token):
    """Pydantic 层类型校验：nrd_offline_enabled 传不可解析类型 → 422。
    （注意 "yes"/"true" 属 Pydantic 宽松可转字符串，会 200——用 list 触发硬错误）"""
    h = {"Authorization": f"Bearer {token}"}
    r = client.put("/api/config", headers=h,
                   json={"nrd_offline_enabled": ["not-a-bool"]})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# 10. reasons 端点 + 筛选排除
# ---------------------------------------------------------------------------

def test_reasons_options_and_exclude(client, token, nrd_offline_env):
    """reasons 端点含 nrd_offline 两项；筛 nrd_offline 不混入
    nrd_offline_observe（LIKE 子串排除）。"""
    h = {"Authorization": f"Bearer {token}"}
    # 造三类日志行
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO filter_log
               (client_ip, domain, query_type, filter_reason, action,
                malicious_ips, final_result, source_api)
               VALUES ('', 'it41-r1.test', 'A', 'nrd_offline',
                       'intercept', '', '', 'hagezi_nrd'),
                      ('', 'it41-r2.test', 'A', 'nrd_offline_observe',
                       'observe', '', '', 'hagezi_nrd'),
                      ('', 'it41-r3.test', 'A', 'nrd_observe',
                       'observe', '', '', 'rdap_nrd')""")
    # reasons 端点
    r = client.get("/api/logs/reasons", headers=h)
    fixed_keys = [x["key"] for x in r.json()["data"]["fixed"]]
    assert "nrd_offline" in fixed_keys
    assert "nrd_offline_observe" in fixed_keys
    # 精确筛 nrd_offline：只命中拦截行，不混入 observe 行
    r = client.get("/api/logs?reason=nrd_offline", headers=h)
    domains = {x["domain"] for x in r.json()["data"]["items"]}
    assert "it41-r1.test" in domains
    assert "it41-r2.test" not in domains      # nrd_offline_observe 被排除
    # 筛 nrd（在线层全部，迭代 40 原语义保留）：命中在线 observe 行，
    # 不混入离线层两键
    r = client.get("/api/logs?reason=nrd&size=200", headers=h)
    domains = {x["domain"] for x in r.json()["data"]["items"]}
    assert "it41-r3.test" in domains
    assert "it41-r1.test" not in domains
    assert "it41-r2.test" not in domains
    # 筛 nrd_offline_observe（最长键无近邻）：精确命中
    r = client.get("/api/logs?reason=nrd_offline_observe", headers=h)
    domains = {x["domain"] for x in r.json()["data"]["items"]}
    assert "it41-r2.test" in domains


# ---------------------------------------------------------------------------
# 辅助 fixture（API 客户端，放末尾避免遮蔽模块级导入）
# ---------------------------------------------------------------------------

@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def token(client):
    r = client.post("/api/auth/login", json={
        "username": "admin", "password": CONFIG.admin_initial_password,
    })
    assert r.status_code == 200
    return r.json()["data"]["token"]
