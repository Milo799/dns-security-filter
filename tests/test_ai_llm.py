"""P3 LLM 智能中枢测试（迭代 49 · AI 能力规划）。

重点验证三件事：
  1. **降级可用性**：未配置 key 时所有能力仍返回可用内容（结构化），
     绝不因缺 LLM 而报错——这是"功能永远可用"的设计红线。
  2. **配置判定**：is_llm_enabled 四要素齐全才为真（开关/URL/key/模型）。
  3. **API 契约**：status 不回传 key 明文；report/summarize/ask 均可用。

涉及 LLM 调用的用例全部 monkeypatch `_chat`，不发真实网络请求。
"""

import json

import pytest
from fastapi.testclient import TestClient

from app.db import db_cursor
from app.main import app
from config import CONFIG

import ai_llm


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def token(client):
    r = client.post("/api/auth/login", json={
        "username": "admin",
        "password": CONFIG.admin_initial_password,
    })
    assert r.status_code == 200
    return r.json()["data"]["token"]


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def llm_env(monkeypatch):
    """隔离 LLM 配置与数据，测试后完整还原（避免全量套件顺序污染）。"""
    saved = {k: getattr(CONFIG, k, None) for k in
             ("llm_enabled", "llm_base_url", "llm_api_key", "llm_model")}
    with db_cursor() as cur:
        cur.execute("DELETE FROM ai_findings")
        cur.execute("DELETE FROM domain_first_seen")
        cur.execute("DELETE FROM nrd_cache WHERE domain LIKE '%llm-test%'")
        cur.execute("DELETE FROM filter_log WHERE domain LIKE '%llm-test%'")
    yield
    for k, v in saved.items():
        setattr(CONFIG, k, v)
    with db_cursor() as cur:
        cur.execute("DELETE FROM ai_findings")
        cur.execute("DELETE FROM domain_first_seen")
        cur.execute("DELETE FROM nrd_cache WHERE domain LIKE '%llm-test%'")
        cur.execute("DELETE FROM filter_log WHERE domain LIKE '%llm-test%'")


def _disable(monkeypatch, **over):
    """把 LLM 配置置为未启用，再按需覆盖字段。"""
    cfg = {"llm_enabled": False, "llm_base_url": "", "llm_api_key": "",
           "llm_model": ""}
    cfg.update(over)
    for k, v in cfg.items():
        monkeypatch.setattr(CONFIG, k, v)


def _enable(monkeypatch):
    _disable(monkeypatch, llm_enabled=True,
             llm_base_url="https://llm.example.com/v1",
             llm_api_key="sk-test", llm_model="test-model")


def _add_finding(type_, target, score=0.8, status="pending", evidence=None):
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO ai_findings (type, target, score, evidence, status)
               VALUES (?, ?, ?, ?, ?)""",
            (type_, target, score,
             json.dumps(evidence or {"clients": 9}, ensure_ascii=False),
             status))


# ---------------------------------------------------------------------------
# 配置判定
# ---------------------------------------------------------------------------


class TestEnabled:
    def test_disabled_by_default(self, llm_env, monkeypatch):
        _disable(monkeypatch)
        assert ai_llm.is_llm_enabled() is False

    def test_requires_all_four(self, llm_env, monkeypatch):
        """四要素缺任一 → 未启用（避免半配置状态发起无效调用）。"""
        full = {"llm_enabled": True, "llm_base_url": "https://x/v1",
                "llm_api_key": "sk", "llm_model": "m"}
        for missing in full:
            cfg = dict(full)
            cfg[missing] = False if missing == "llm_enabled" else ""
            _disable(monkeypatch, **cfg)
            assert ai_llm.is_llm_enabled() is False, missing
        _disable(monkeypatch, **full)
        assert ai_llm.is_llm_enabled() is True

    def test_whitespace_key_not_counted(self, llm_env, monkeypatch):
        _disable(monkeypatch, llm_enabled=True, llm_base_url="https://x/v1",
                 llm_api_key="   ", llm_model="m")
        assert ai_llm.is_llm_enabled() is False


# ---------------------------------------------------------------------------
# 降级：未配置 LLM 时功能仍可用
# ---------------------------------------------------------------------------


class TestStructuredFallback:
    def test_report_without_llm(self, llm_env, monkeypatch):
        _disable(monkeypatch)
        _add_finding("dga_suspect", "xj3k9d2mz7qp.icu", 0.71)
        r = ai_llm.generate_daily_report()
        assert r["source"] == "structured"
        assert "xj3k9d2mz7qp.icu" in r["content"]
        assert "疑似 DGA 域名" in r["content"]

    def test_report_empty_state(self, llm_env, monkeypatch):
        _disable(monkeypatch)
        r = ai_llm.generate_daily_report()
        assert r["source"] == "structured"
        assert r["content"]

    def test_summarize_without_llm(self, llm_env, monkeypatch):
        _disable(monkeypatch)
        _add_finding("dga_suspect", "llm-test-bad.icu", 0.66)
        r = ai_llm.summarize_domain("llm-test-bad.icu")
        assert r["source"] == "structured"
        assert r["content"]
        assert r["facts"]["domain"] == "llm-test-bad.icu"
        assert r["facts"]["ai_findings"]

    def test_summarize_unknown_domain(self, llm_env, monkeypatch):
        _disable(monkeypatch)
        r = ai_llm.summarize_domain("llm-test-nowhere.com")
        assert r["source"] == "structured"
        assert "暂无 AI 判定结论" in r["content"]

    def test_summarize_invalid_domain(self, llm_env, monkeypatch):
        _disable(monkeypatch)
        r = ai_llm.summarize_domain("   ")
        assert r["content"]

    def test_summarize_uses_case_and_dot_normalization(self, llm_env,
                                                       monkeypatch):
        _disable(monkeypatch)
        _add_finding("false_positive", "llm-test-norm.com", 0.6)
        r = ai_llm.summarize_domain("LLM-Test-Norm.COM.")
        assert r["facts"]["domain"] == "llm-test-norm.com"
        assert r["facts"]["ai_findings"]

    def test_ask_without_llm(self, llm_env, monkeypatch):
        _disable(monkeypatch)
        r = ai_llm.ask("今天有什么可疑的？")
        assert r["source"] == "structured"
        assert "未配置 LLM" in r["content"]

    def test_ask_empty_question(self, llm_env, monkeypatch):
        _disable(monkeypatch)
        r = ai_llm.ask("   ")
        assert "请提供问题" in r["content"]


# ---------------------------------------------------------------------------
# LLM 路径（_chat 被替身，不发网络）
# ---------------------------------------------------------------------------


class TestLLMPath:
    def test_report_uses_llm(self, llm_env, monkeypatch):
        _enable(monkeypatch)
        _add_finding("threat_cluster", "evil-c2.top", 0.9)
        monkeypatch.setattr(ai_llm, "_chat", lambda msgs, **kw: "今日态势平稳。")
        r = ai_llm.generate_daily_report()
        assert r["source"] == "llm"
        assert r["content"] == "今日态势平稳。"

    def test_ask_uses_llm(self, llm_env, monkeypatch):
        _enable(monkeypatch)
        monkeypatch.setattr(ai_llm, "_chat", lambda msgs, **kw: "共 0 项待确认。")
        r = ai_llm.ask("有多少待确认？")
        assert r["source"] == "llm"

    def test_llm_failure_degrades(self, llm_env, monkeypatch):
        """LLM 报错绝不能把功能拖死——降级回结构化。"""
        _enable(monkeypatch)
        _add_finding("dga_suspect", "llm-test-fail.icu", 0.7)

        def boom(msgs, **kw):
            raise RuntimeError("connection reset")
        monkeypatch.setattr(ai_llm, "_chat", boom)

        r1 = ai_llm.generate_daily_report()
        assert r1["source"] == "structured"
        assert "llm-test-fail.icu" in r1["content"]
        r2 = ai_llm.summarize_domain("llm-test-fail.icu")
        assert r2["source"] == "structured"
        r3 = ai_llm.ask("问题")
        assert r3["source"] == "structured"

    def test_chat_builds_openai_compatible_request(self, llm_env, monkeypatch):
        """_chat 的请求形状：Bearer 鉴权 + chat/completions + 代理注入。"""
        _disable(monkeypatch, llm_enabled=True,
                 llm_base_url="https://llm.example.com/v1/",
                 llm_api_key="sk-abc", llm_model="m1")
        monkeypatch.setattr(CONFIG, "http_proxy", "http://proxy:3128")
        seen = {}

        class FakeResp:
            def raise_for_status(self):
                pass

            def json(self):
                return {"choices": [{"message": {"content": "  ok  "}}]}
        import requests

        def fake_post(url, headers=None, json=None, timeout=None, proxies=None):
            seen.update(url=url, headers=headers, body=json, proxies=proxies)
            return FakeResp()
        monkeypatch.setattr(requests, "post", fake_post)

        out = ai_llm._chat([{"role": "user", "content": "hi"}])
        assert out == "ok"                        # 首尾空白已 strip
        assert seen["url"] == "https://llm.example.com/v1/chat/completions"
        assert seen["headers"]["Authorization"] == "Bearer sk-abc"
        assert seen["body"]["model"] == "m1"
        assert seen["proxies"] == {"http": "http://proxy:3128",
                                   "https": "http://proxy:3128"}


# ---------------------------------------------------------------------------
# 数据汇总（喂 LLM 的事实来源）
# ---------------------------------------------------------------------------


class TestCollect:
    def test_collect_groups_by_type(self, llm_env, monkeypatch):
        _disable(monkeypatch)
        _add_finding("dga_suspect", "a.icu", 0.9)
        _add_finding("dga_suspect", "b.icu", 0.5)
        _add_finding("client_anomaly", "10.0.0.9|evil.com", 0.8)
        _add_finding("tunnel_suspect", "10.0.0.1|t.com", 0.7, status="dismissed")
        out = ai_llm.collect_findings()
        assert [i["target"] for i in out["dga_suspect"]] == ["a.icu", "b.icu"]
        assert "client_anomaly" in out
        assert "tunnel_suspect" not in out       # 非 pending 不收集

    def test_collect_limit_per_type(self, llm_env, monkeypatch):
        _disable(monkeypatch)
        for i in range(5):
            _add_finding("dga_suspect", f"d{i}.icu", 0.5 + i * 0.05)
        out = ai_llm.collect_findings(limit_per_type=3)
        assert len(out["dga_suspect"]) == 3

    def test_collect_tolerates_bad_evidence_json(self, llm_env, monkeypatch):
        _disable(monkeypatch)
        with db_cursor() as cur:
            cur.execute(
                """INSERT INTO ai_findings (type, target, score, evidence)
                   VALUES ('dga_suspect', 'broken.icu', 0.5, 'not-json')""")
        out = ai_llm.collect_findings()
        assert out["dga_suspect"][0]["evidence"] == {}


# ---------------------------------------------------------------------------
# API 契约
# ---------------------------------------------------------------------------


class TestAPI:
    @pytest.fixture
    def cli(self, client, token):
        return client, {"Authorization": "Bearer " + token}

    def test_status_hides_key(self, cli, llm_env, monkeypatch):
        client, h = cli
        _disable(monkeypatch, llm_enabled=True,
                 llm_base_url="https://llm.example.com/v1",
                 llm_api_key="sk-SECRET-DO-NOT-LEAK", llm_model="m1")
        r = client.get("/api/ai/llm/status", headers=h)
        assert r.status_code == 200
        d = r.json()["data"]
        assert d["mode"] == "llm"
        assert d["api_key_configured"] is True
        assert "sk-SECRET-DO-NOT-LEAK" not in json.dumps(d)

    def test_status_structured_mode(self, cli, llm_env, monkeypatch):
        client, h = cli
        _disable(monkeypatch)
        d = client.get("/api/ai/llm/status", headers=h).json()["data"]
        assert d["mode"] == "structured"
        assert d["api_key_configured"] is False

    def test_report_endpoint(self, cli, llm_env, monkeypatch):
        client, h = cli
        _disable(monkeypatch)
        _add_finding("threat_cluster", "evil-c2.top", 0.9)
        r = client.post("/api/ai/llm/report", headers=h)
        assert r.status_code == 200
        d = r.json()["data"]
        assert d["source"] == "structured"
        assert "evil-c2.top" in d["content"]

    def test_summarize_endpoint(self, cli, llm_env, monkeypatch):
        client, h = cli
        _disable(monkeypatch)
        _add_finding("dga_suspect", "llm-test-api.icu", 0.7)
        r = client.post("/api/ai/llm/summarize?domain=llm-test-api.icu",
                        headers=h)
        assert r.status_code == 200
        assert r.json()["data"]["facts"]["domain"] == "llm-test-api.icu"

    def test_ask_endpoint(self, cli, llm_env, monkeypatch):
        client, h = cli
        _disable(monkeypatch)
        r = client.post("/api/ai/llm/ask?question=%E6%9C%89%E4%BB%80%E4%B9%88",
                        headers=h)
        assert r.status_code == 200
        assert r.json()["data"]["content"]

    def test_endpoints_require_auth(self, client, llm_env):
        assert client.get("/api/ai/llm/status").status_code in (401, 403)
        assert client.post("/api/ai/llm/report").status_code in (401, 403)
