"""MCP 服务测试（迭代 50）。

覆盖：
  1. ApiClient：登录、token 复用、401 重登一次、业务错误码转异常；
  2. 只读工具：系统状态、域名处置判定、域名画像、名单/日志/结论查询、
     情报源、AI 日报与问答（未配 LLM 时的结构化降级）；
  3. 写工具三重闸门：只读模式拒绝 / 缺 confirm 拒绝 / confirm 后落库
     + 平台审计归属（operator=mcp:<agent>）；
  4. 误伤治理闭环：误报清单 → false_positive_whitelist → 白名单 + 结论
     confirmed；
  5. 名单条目启停/删除、AI 结论决断；
  6. MCP 协议层：工具与提示词注册完整、JSON Schema 含参数。

关键手法：把 MCP 的 HTTP 层（mcp_server._http）替换为进程内
TestClient——工具代码零改动，但请求真实穿过平台的鉴权/校验/审计/DB。

运行：cd platform && python -m pytest ../tests/test_mcp_server.py -v
"""

import asyncio
import json

import pytest
from fastapi.testclient import TestClient

pytest.importorskip("mcp.server.mcpserver")   # 未装 MCP SDK 时跳过

from app.db import db_cursor, invalidate_list_cache
from app.main import app
from config import CONFIG

import mcp_server

FAKE_BASE = "http://platform.test"
AGENT = "test-agent"


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tc():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def mcp_env(tc, monkeypatch):
    """把 MCP 的 HTTP 层接到进程内平台实例（真实 API + 测试 DB）。"""
    settings = mcp_server.Settings(
        api_base=FAKE_BASE, api_user="admin",
        api_password=CONFIG.admin_initial_password,
        agent_name=AGENT, allow_write=True)

    def fake_http(method, url, *, headers=None, params=None, json_body=None,
                  timeout=20.0):
        assert url.startswith(FAKE_BASE), url
        path = url[len(FAKE_BASE):] or "/"
        r = tc.request(method, path, headers=headers, params=params,
                       json=json_body)
        try:
            payload = r.json()
        except ValueError:
            payload = {"_raw": r.text[:200]}
        return r.status_code, payload

    monkeypatch.setattr(mcp_server, "_http", fake_http)
    mcp_server.configure(settings=settings)
    mcp_server._client = None            # 丢弃上一测试的登录态
    yield settings
    mcp_server.configure(settings=mcp_server.Settings.from_env())
    mcp_server._client = None
    # 清理本文件写入的行，防污染后续测试（threat_list/filter_list 残留
    # 会串扰名单断言与真实性下载路径）
    with db_cursor() as cur:
        cur.execute("DELETE FROM filter_list WHERE value LIKE 'mcp-test%'")
        cur.execute("DELETE FROM filter_list WHERE value LIKE '%mcp%test%'")
        cur.execute("DELETE FROM ai_findings WHERE target LIKE '%mcp-test%'")
        cur.execute("DELETE FROM audit_log WHERE operator LIKE 'mcp:%'")
        cur.execute("DELETE FROM filter_log WHERE domain LIKE '%mcp-test%'")
    invalidate_list_cache()


def _add_blacklist(value, target="domain"):
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO filter_list (list_type, target, value, enabled,
                                        remark, created_by)
               VALUES ('blacklist', ?, ?, 1, 'MCP 测试', 'test')""",
            (target, value))
        item_id = cur.lastrowid
    invalidate_list_cache()
    return item_id


def _add_finding(ftype, target, score=0.8, status="pending"):
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO ai_findings (type, target, score, evidence, status)
               VALUES (?, ?, ?, ?, ?)""",
            (ftype, target, score, json.dumps({"clients": 9,
                                               "note": "mcp-test"}),
             status))
    return True


def _whitelist_values():
    with db_cursor() as cur:
        cur.execute("SELECT value FROM filter_list WHERE list_type='whitelist'")
        return {r["value"] for r in cur.fetchall()}


def _audit_rows(operator_like="mcp:%"):
    with db_cursor() as cur:
        cur.execute("SELECT operator, action, detail FROM audit_log "
                    "WHERE operator LIKE ? ORDER BY id", (operator_like,))
        return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# 1. API 客户端
# ---------------------------------------------------------------------------


class TestApiClient:
    def test_login_and_reuse_token(self, tc, monkeypatch):
        calls = {"login": 0, "auth": 0}

        def fake_http(method, url, *, headers=None, params=None,
                      json_body=None, timeout=20.0):
            if url.endswith("/api/auth/login"):
                calls["login"] += 1
                return 200, {"code": 0, "data": {"token": "tok-1"}}
            calls["auth"] += 1
            return 200, {"code": 0, "data": {"ok": True}}
        monkeypatch.setattr(mcp_server, "_http", fake_http)

        c = mcp_server.ApiClient(mcp_server.Settings(
            api_base=FAKE_BASE, api_user="admin", api_password="x"))
        assert c.call("GET", "/api/status") == {"ok": True}
        assert c.call("GET", "/api/status") == {"ok": True}
        assert calls["login"] == 1, "token 应被复用（只登录一次）"
        assert calls["auth"] == 2

    def test_relogin_on_401_once(self, monkeypatch):
        state = {"token": "old", "logins": 0}

        def fake_http(method, url, *, headers=None, params=None,
                      json_body=None, timeout=20.0):
            if url.endswith("/api/auth/login"):
                state["logins"] += 1
                state["token"] = f"tok-{state['logins']}"
                return 200, {"code": 0, "data": {"token": state["token"]}}
            if headers.get("Authorization") == "Bearer old":
                return 401, {"detail": "token expired"}
            return 200, {"code": 0, "data": {"ok": True}}
        monkeypatch.setattr(mcp_server, "_http", fake_http)

        c = mcp_server.ApiClient(mcp_server.Settings(
            api_base=FAKE_BASE, api_user="admin", api_password="x"))
        c._token = "old"
        assert c.call("GET", "/api/status") == {"ok": True}
        assert state["logins"] == 1

    def test_login_failure_raises(self, monkeypatch):
        monkeypatch.setattr(mcp_server, "_http", lambda *a, **k: (
            401, {"code": 1, "message": "用户名或密码错误"}))
        c = mcp_server.ApiClient(mcp_server.Settings(
            api_base=FAKE_BASE, api_user="admin", api_password="bad"))
        with pytest.raises(mcp_server.ApiError) as ei:
            c.call("GET", "/api/status")
        assert "登录失败" in str(ei.value)

    def test_business_error_raises(self, monkeypatch):
        def fake_http(method, url, **kw):
            if url.endswith("/api/auth/login"):
                return 200, {"code": 0, "data": {"token": "t"}}
            return 200, {"code": 1, "message": "域名格式非法"}
        monkeypatch.setattr(mcp_server, "_http", fake_http)
        c = mcp_server.ApiClient(mcp_server.Settings(
            api_base=FAKE_BASE, api_user="admin", api_password="x"))
        with pytest.raises(mcp_server.ApiError) as ei:
            c.call("POST", "/api/test/domain", body={"domain": "bad"})
        assert "域名格式非法" in str(ei.value)

    def test_settings_from_env(self):
        s = mcp_server.Settings.from_env({
            "DNSF_API_BASE": "http://1.2.3.4:8080/",
            "DNSF_API_PASSWORD": "pw", "DNSF_MCP_ALLOW_WRITE": "0",
            "DNSF_MCP_AGENT": "my-agent", "DNSF_MCP_PORT": "9000"})
        assert s.api_base == "http://1.2.3.4:8080"
        assert s.allow_write is False
        assert s.agent_name == "my-agent" and s.port == 9000
        # 缺省值
        d = mcp_server.Settings.from_env({})
        assert d.api_base.endswith(":8080") and d.allow_write is True
        assert d.api_user == "admin" and d.transport == "stdio"


# ---------------------------------------------------------------------------
# 2. 只读工具
# ---------------------------------------------------------------------------


class TestReadTools:
    def test_system_status_shape(self, mcp_env, mcp_env_db=False):
        d = mcp_server.system_status()
        assert set(d) >= {"detection_enabled", "traffic", "layers", "ai",
                          "sources", "health"}
        assert set(d["traffic"]) >= {"today_total", "today_intercepts",
                                     "intercept_rate_pct"}
        assert isinstance(d["layers"], list)
        assert set(d["ai"]) == {"first_seen_total", "first_seen_24h",
                                "pending_findings"}
        assert set(d["sources"]) >= {"offline_enabled", "online_enabled"}

    def test_domain_verdict_intercept(self, mcp_env):
        _add_blacklist("mcp-test-blocked.com")
        d = mcp_server.domain_verdict("mcp-test-blocked.com")
        assert d["final_verdict"]["action"] == "intercept"
        assert "本地黑名单" in d["local_blacklist"]["rule"] or \
               d["local_blacklist"]["matched"] is True

    def test_domain_verdict_allow(self, mcp_env):
        d = mcp_server.domain_verdict("www.baidu.com")
        assert d["domain"] == "www.baidu.com"

    def test_domain_verdict_empty(self, mcp_env):
        assert "error" in mcp_server.domain_verdict("   ")

    def test_domain_investigate_composes(self, mcp_env):
        _add_blacklist("mcp-test-inv.com")
        _add_finding("dga_suspect", "mcp-test-inv.com", 0.71)
        with db_cursor() as cur:
            cur.execute(
                """INSERT INTO filter_log (client_ip, domain, query_type,
                       filter_reason, action, malicious_ips, final_result,
                       source_api)
                   VALUES ('10.0.0.1', 'mcp-test-inv.com', 'A',
                           'local_blacklist', 'intercept', '',
                           'alert_ip:127.0.0.1', '')""")
        d = mcp_server.domain_investigate("MCP-Test-Inv.com.")
        assert d["domain"] == "mcp-test-inv.com"          # 归一化
        assert d["verdict"]["final_verdict"]["action"] == "intercept"
        assert d["list_entries"], "应返回命中的名单条目"
        assert d["recent_logs"] and d["recent_logs"][0]["domain"] == \
            "mcp-test-inv.com"
        assert d["summary"] and d["summary_source"] in ("llm", "structured")

    def test_list_query_finds_entry(self, mcp_env):
        item_id = _add_blacklist("mcp-test-list.com")
        d = mcp_server.list_query(keyword="mcp-test-list")
        ids = [i["id"] for i in d["items"]]
        assert item_id in ids
        assert d["items"][0]["level"] in ("tld", "registrable", "subdomain")

    def test_ai_findings_filter_by_type(self, mcp_env):
        _add_finding("dga_suspect", "mcp-test-dga.icu", 0.66)
        _add_finding("tunnel_suspect", "10.0.0.1|mcp-test-tun.com", 0.9)
        dga = mcp_server.ai_findings(finding_type="dga_suspect")
        assert all(i["type"] == "dga_suspect"
                   for i in dga["items"])
        assert any(i["target"] == "mcp-test-dga.icu" for i in dga["items"])
        tun = mcp_server.ai_findings(finding_type="tunnel_suspect")
        assert any(i["target"] == "10.0.0.1|mcp-test-tun.com"
                   for i in tun["items"])

    def test_ai_findings_status_all(self, mcp_env):
        _add_finding("dga_suspect", "mcp-test-done.icu", 0.7,
                     status="dismissed")
        pend = mcp_server.ai_findings(finding_type="dga_suspect")
        allst = mcp_server.ai_findings(finding_type="dga_suspect", status="")
        assert not any(i["target"] == "mcp-test-done.icu"
                       for i in pend["items"])
        assert any(i["target"] == "mcp-test-done.icu" for i in allst["items"])

    def test_traffic_stats(self, mcp_env):
        d = mcp_server.traffic_stats(hours=6)
        assert set(d) == {"today", "hourly", "layers"}

    def test_logs_query_by_domain(self, mcp_env):
        with db_cursor() as cur:
            cur.execute(
                """INSERT INTO filter_log (client_ip, domain, query_type,
                       filter_reason, action, malicious_ips, final_result,
                       source_api)
                   VALUES ('10.9.9.9', 'mcp-test-log.top', 'A',
                           'threat_list:silverfox', 'intercept', '',
                           'alert_ip:127.0.0.1', 'silverfox')""")
        d = mcp_server.logs_query(domain="mcp-test-log.top")
        assert d["total"] >= 1
        assert d["items"][0]["filter_reason"] == "threat_list:silverfox"

    def test_intel_sources(self, mcp_env):
        d = mcp_server.intel_sources()
        assert set(d) == {"offline", "online", "quality"}
        assert "items" in d["offline"]

    def test_ai_report_structured_fallback(self, mcp_env):
        d = mcp_server.ai_report()
        assert d["source"] in ("llm", "structured")
        assert d["content"]

    def test_ai_ask_requires_question(self, mcp_env):
        assert "error" in mcp_server.ai_ask("  ")
        d = mcp_server.ai_ask("今天有什么可疑的？")
        assert d["content"]

    def test_api_error_becomes_structured_error(self, mcp_env, monkeypatch):
        def boom(*a, **k):
            raise mcp_server.ApiError("模拟平台故障", 500, {"detail": "x"})
        monkeypatch.setattr(mcp_server.ApiClient, "call", boom)
        d = mcp_server.ai_report()
        assert d["ok"] is False and "模拟平台故障" in d["error"]
        assert d["status"] == 500


# ---------------------------------------------------------------------------
# 3. 写守卫
# ---------------------------------------------------------------------------


WRITE_CALLS = [
    ("whitelist_add", dict(value="mcp-test-w1.com")),
    ("blacklist_add", dict(value="mcp-test-w2.com")),
    ("list_entry_set_enabled", dict(item_id=1, enabled=False)),
    ("list_entry_delete", dict(item_id=1)),
    ("finding_decide", dict(finding_id=1, status="confirmed")),
    ("false_positive_whitelist", dict(domain="mcp-test-w3.com")),
]


class TestWriteGuard:
    @pytest.mark.parametrize("tool,kwargs", WRITE_CALLS)
    def test_requires_confirmation(self, mcp_env, tool, kwargs):
        """未确认 → 拒绝 + 回传待确认动作（红线：AI 只出建议）。"""
        d = getattr(mcp_server, tool)(**kwargs)
        assert d["ok"] is False
        assert d["rejected"] == "needs_confirmation"
        assert d["pending_action"]
        assert "向用户说明" in d["message"]

    def test_no_db_change_without_confirm(self, mcp_env):
        before = _whitelist_values()
        mcp_server.whitelist_add(value="mcp-test-nc.com")
        assert "mcp-test-nc.com" not in _whitelist_values()
        assert _whitelist_values() == before

    def test_readonly_mode_rejects_all(self, mcp_env, monkeypatch):
        mcp_env.allow_write = False
        for tool, kwargs in WRITE_CALLS:
            d = getattr(mcp_server, tool)(confirm=True, **kwargs)
            assert d["ok"] is False, tool
            assert d["rejected"] == "write_disabled", tool
        # 只读工具不受影响
        assert "ok" not in mcp_server.intel_sources()

    def test_whitelist_add_confirmed_writes_and_audits(self, mcp_env):
        d = mcp_server.whitelist_add(value="mcp-test-ok.com",
                                     remark="MCP 测试加白", confirm=True)
        assert d["ok"] is True
        assert "mcp-test-ok.com" in _whitelist_values()
        assert "生效延迟" in d["note"]
        rows = _audit_rows()
        assert any(r["action"] == "mcp_whitelist_add"
                   and r["operator"] == "mcp:" + AGENT for r in rows), rows
        # 平台自身的名单审计也在（双留痕）
        assert any(r["action"] == "list_create" for r in rows) is False

    def test_whitelist_add_platform_audit_exists(self, mcp_env):
        mcp_server.whitelist_add(value="mcp-test-audit.com", confirm=True)
        with db_cursor() as cur:
            cur.execute("SELECT operator, action FROM audit_log "
                        "WHERE action='list_create' ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
        assert row and row["action"] == "list_create"

    def test_blacklist_add_confirmed(self, mcp_env):
        d = mcp_server.blacklist_add(value="mcp-test-bl.com", confirm=True)
        assert d["ok"] is True
        verdict = mcp_server.domain_verdict("mcp-test-bl.com")
        assert verdict["final_verdict"]["action"] == "intercept"

    def test_duplicate_whitelist_is_idempotent(self, mcp_env):
        """重复加白不产生重复条目（平台列表接口无查重，MCP 侧写前自查）。"""
        first = mcp_server.whitelist_add(value="mcp-test-dup.com",
                                         confirm=True)
        assert first["ok"] is True and "already_present" not in first
        second = mcp_server.whitelist_add(value="mcp-test-dup.com",
                                          confirm=True)
        assert second["ok"] is True and second["already_present"] is True
        assert second["existing"]["value"] == "mcp-test-dup.com"
        with db_cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM filter_list "
                        "WHERE list_type='whitelist' AND value=?",
                        ("mcp-test-dup.com",))
            assert cur.fetchone()["n"] == 1

    def test_duplicate_blacklist_is_idempotent(self, mcp_env):
        mcp_server.blacklist_add(value="mcp-test-bl-dup.com", confirm=True)
        d = mcp_server.blacklist_add(value="mcp-test-bl-dup.com",
                                     confirm=True)
        assert d["already_present"] is True

    def test_list_entry_set_enabled(self, mcp_env):
        item_id = _add_blacklist("mcp-test-toggle.com")
        d = mcp_server.list_entry_set_enabled(item_id=item_id, enabled=False,
                                              confirm=True)
        assert d["ok"] is True
        with db_cursor() as cur:
            cur.execute("SELECT enabled FROM filter_list WHERE id=?",
                        (item_id,))
            assert cur.fetchone()["enabled"] == 0
        assert any(r["action"] == "mcp_list_entry_set_enabled"
                   for r in _audit_rows())

    def test_list_entry_delete(self, mcp_env):
        item_id = _add_blacklist("mcp-test-del.com")
        d = mcp_server.list_entry_delete(item_id=item_id, confirm=True)
        assert d["ok"] is True
        with db_cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM filter_list WHERE id=?",
                        (item_id,))
            assert cur.fetchone()["n"] == 0

    def test_finding_decide_rejects_bad_status(self, mcp_env):
        d = mcp_server.finding_decide(finding_id=1, status="maybe",
                                      confirm=True)
        assert "error" in d

    def test_finding_decide_confirmed(self, mcp_env):
        _add_finding("dga_suspect", "mcp-test-decide.icu", 0.8)
        with db_cursor() as cur:
            cur.execute("SELECT id FROM ai_findings WHERE target=?",
                        ("mcp-test-decide.icu",))
            fid = cur.fetchone()["id"]
        d = mcp_server.finding_decide(finding_id=fid, status="confirmed",
                                      confirm=True)
        assert d["ok"] is True
        with db_cursor() as cur:
            cur.execute("SELECT status FROM ai_findings WHERE id=?", (fid,))
            assert cur.fetchone()["status"] == "confirmed"
        assert any(r["action"] == "mcp_finding_decide"
                   for r in _audit_rows())

    def test_false_positive_whitelist_closes_loop(self, mcp_env):
        _add_finding("false_positive", "mcp-test-fp.com", 0.88)
        d = mcp_server.false_positive_whitelist(domain="mcp-test-fp.com",
                                                remark="确认误伤",
                                                confirm=True)
        assert d["ok"] is True
        assert "mcp-test-fp.com" in _whitelist_values()
        with db_cursor() as cur:
            cur.execute("SELECT status FROM ai_findings WHERE target=? "
                        "AND type='false_positive'", ("mcp-test-fp.com",))
            assert cur.fetchone()["status"] == "confirmed"
        # 白名单生效：处置结果转为放行
        v = mcp_server.domain_verdict("mcp-test-fp.com")
        assert v["final_verdict"]["action"] == "allow"

    def test_false_positive_whitelist_empty_domain(self, mcp_env):
        d = mcp_server.false_positive_whitelist(domain="  ", confirm=True)
        assert "error" in d


# ---------------------------------------------------------------------------
# 4. MCP 协议层
# ---------------------------------------------------------------------------


class TestProtocol:
    def test_all_tools_registered(self):
        tools = asyncio.run(mcp_server.server.list_tools())
        names = {t.name for t in tools}
        assert names == {
            "system_status", "domain_verdict", "domain_investigate",
            "list_query", "ai_findings", "traffic_stats", "logs_query",
            "intel_sources", "ai_report", "ai_ask",
            "whitelist_add", "blacklist_add", "list_entry_set_enabled",
            "list_entry_delete", "finding_decide",
            "false_positive_whitelist",
        }, names

    def test_tool_schema_has_parameters(self):
        """写工具的 confirm 必须出现在 schema 里（包裹装饰器不能吃掉签名）。"""
        tools = {t.name: t for t in asyncio.run(
            mcp_server.server.list_tools())}
        props = tools["whitelist_add"].input_schema["properties"]
        assert "value" in props and "confirm" in props
        assert tools["whitelist_add"].input_schema["required"] == ["value"]
        props2 = tools["domain_verdict"].input_schema["properties"]
        assert "domain" in props2 and "query_type" in props2

    def test_tool_descriptions_present(self):
        tools = asyncio.run(mcp_server.server.list_tools())
        for t in tools:
            assert t.description and len(t.description) > 30, t.name

    def test_prompts_registered(self):
        prompts = asyncio.run(mcp_server.server.list_prompts())
        names = {p.name for p in prompts}
        assert {"investigate_domain", "daily_briefing"} <= names

    def test_server_instructions_mention_redline(self):
        assert "红线" in mcp_server.server.instructions
        assert "confirm=true" in mcp_server.server.instructions

    def test_bearer_middleware_blocks_without_token(self):
        """http 传输：无 token → 401；正确 token → 放行。"""
        import asyncio as aio

        async def run(header):
            seen = {}

            async def inner(scope, receive, send):
                seen["passed"] = True
                await send({"type": "http.response.start", "status": 200,
                            "headers": []})
                await send({"type": "http.response.body", "body": b"ok"})

            mw = mcp_server.BearerAuthMiddleware(inner, token="secret")
            sent = []

            async def send(msg):
                sent.append(msg)
            scope = {"type": "http", "path": "/mcp", "headers": header}
            await mw(scope, None, send)
            return seen.get("passed"), sent[0]["status"]

        passed, status = aio.run(run([]))
        assert passed is None and status == 401
        passed, status = aio.run(run([(b"authorization", b"Bearer secret")]))
        assert passed is True and status == 200

    def test_bearer_middleware_disabled_when_no_token(self):
        import asyncio as aio

        async def run():
            async def inner(scope, receive, send):
                await send({"type": "http.response.start", "status": 200,
                            "headers": []})
                await send({"type": "http.response.body", "body": b"ok"})
            mw = mcp_server.BearerAuthMiddleware(inner, token="")
            sent = []

            async def send(msg):
                sent.append(msg)
            await mw({"type": "http", "path": "/mcp", "headers": []},
                     None, send)
            return sent[0]["status"]

        assert aio.run(run()) == 200


# ---------------------------------------------------------------------------
# 5. 平台侧审计端点
# ---------------------------------------------------------------------------


class TestPlatformAuditEndpoint:
    def test_mcp_audit_writes_row(self, tc):
        tok = tc.post("/api/auth/login", json={
            "username": "admin",
            "password": CONFIG.admin_initial_password}).json()["data"]["token"]
        r = tc.post("/api/mcp/audit",
                    headers={"Authorization": "Bearer " + tok},
                    json={"tool": "whitelist_add",
                          "operator": "mcp:unit-test",
                          "detail": {"value": "x.com"}})
        assert r.status_code == 200
        assert r.json()["data"]["action"] == "mcp_whitelist_add"
        with db_cursor() as cur:
            cur.execute("SELECT operator, action FROM audit_log "
                        "WHERE operator='mcp:unit-test'")
            row = cur.fetchone()
        assert row["action"] == "mcp_whitelist_add"
        with db_cursor() as cur:
            cur.execute("DELETE FROM audit_log WHERE operator='mcp:unit-test'")

    def test_mcp_audit_requires_auth(self, tc):
        r = tc.post("/api/mcp/audit", json={"tool": "x"})
        assert r.status_code in (401, 403)

    def test_mcp_audit_readable_label(self, mcp_env):
        """审计可读化：MCP 动作在审计查询里显示中文标签。"""
        mcp_server.whitelist_add(value="mcp-test-label.com", confirm=True)
        with db_cursor() as cur:
            cur.execute("SELECT id FROM audit_log "
                        "WHERE action='mcp_whitelist_add' ORDER BY id DESC")
            row = cur.fetchone()
        assert row, "应有 MCP 审计行"
        from app.audit import humanize
        assert humanize("mcp_whitelist_add", {}) == "MCP 加白名单"
