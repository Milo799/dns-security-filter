"""误报识别测试（迭代 49 · AI 能力规划 P1-1）。

覆盖：
  1. false_positive_score 算法区分度（业务域高分 / 可疑域低分）；
  2. analyze_false_positive：多客户端共访的被拦域 → 疑似误伤结论；
  3. 单客户端 / 少量客户端拦截不产生误报结论（降噪）；
  4. ip_filter 类拦截不参与误报识别（语义不同）；
  5. 一键加白接口：写入白名单 + 结论标记 confirmed + 审计 + 重复 409；
  6. /api/ai/false-positive 视图含 already_whitelisted 标注。

运行：cd platform && python -m pytest ../tests/test_ai_false_positive.py -v
"""

import json

import pytest
from fastapi.testclient import TestClient

import ai_analysis
import ai_batch
from app.main import app
from app.db import db_cursor, invalidate_list_cache
from config import CONFIG


# ---------------------------------------------------------------------------
# 1. 算法
# ---------------------------------------------------------------------------


class TestScore:
    def test_business_domain_scores_high(self):
        s, ev = ai_analysis.false_positive_score(
            clients=10, hits=40, hour_ratio=0.85, domain_age_days=3000,
            in_first_seen=True, label="mail-partner")
        assert s >= ai_analysis.FP_THRESHOLD
        assert ev["clients"] == 10
        assert ev["biz_label_hit"] is True          # "mail" 命中业务词表
        assert set(ev["contributions"]) == {
            "clients", "retry", "hours", "age", "seen", "biz"}

    def test_brand_label_not_biz_word(self):
        """品牌名（github）非业务词——不应靠"业务词"得分，靠其他特征。"""
        s, ev = ai_analysis.false_positive_score(
            clients=10, hits=40, hour_ratio=0.85, domain_age_days=3000,
            in_first_seen=True, label="github")
        assert ev["biz_label_hit"] is False
        assert s >= ai_analysis.FP_THRESHOLD        # 其余特征足以判定

    def test_malicious_domain_scores_low(self):
        s, _ = ai_analysis.false_positive_score(
            clients=1, hits=30, hour_ratio=0.10, domain_age_days=5,
            in_first_seen=False, label="kq3vz8xw2m")
        assert s < ai_analysis.FP_THRESHOLD

    def test_unknown_age_neutral(self):
        """年龄未知取中性分——不应因此被误判为高或低。"""
        s, ev = ai_analysis.false_positive_score(
            clients=5, hits=12, hour_ratio=0.7, domain_age_days=None,
            in_first_seen=False, label="")
        assert ev["domain_age_days"] is None
        assert 0 < s < 1


# ---------------------------------------------------------------------------
# 2/3/4. 批处理
# ---------------------------------------------------------------------------


@pytest.fixture
def fp_env():
    with db_cursor() as cur:
        cur.execute("DELETE FROM filter_log")
        cur.execute("DELETE FROM ai_findings")
        cur.execute("DELETE FROM domain_first_seen")
    invalidate_list_cache()
    yield
    with db_cursor() as cur:
        cur.execute("DELETE FROM filter_log")
        cur.execute("DELETE FROM ai_findings")
        cur.execute("DELETE FROM domain_first_seen")
    invalidate_list_cache()


def _add_intercepts(domain, clients, hits_each=1, hour="10", reason="threat_list:silverfox"):
    with db_cursor() as cur:
        for c in range(clients):
            for _ in range(hits_each):
                cur.execute(
                    """INSERT INTO filter_log
                       (client_ip, domain, query_type, filter_reason, action,
                        malicious_ips, final_result, source_api, timestamp)
                       VALUES (?, ?, 'A', ?, 'intercept', '',
                               'alert_ip:127.0.0.1', 'silverfox',
                               datetime('now','localtime'))""",
                    (f"10.0.0.{c + 1}", domain, reason))


class TestAnalyze:
    def test_multi_client_intercept_flagged(self, fp_env):
        _add_intercepts("github.com", clients=8, hits_each=4)
        hits = ai_batch.analyze_false_positive()
        assert any(d == "github.com" for d, _, _ in hits)
        score = [s for d, s, _ in hits if d == "github.com"][0]
        assert score >= ai_analysis.FP_THRESHOLD

    def test_single_client_not_flagged(self, fp_env):
        _add_intercepts("evil-single.top", clients=1, hits_each=20)
        hits = ai_batch.analyze_false_positive()
        assert not any(d == "evil-single.top" for d, _, _ in hits)

    def test_ip_filter_excluded(self, fp_env):
        """ip_filter 类拦截不参与误报识别（IP 后置语义不同）。"""
        _add_intercepts("cdn-hosting.com", clients=8, hits_each=3,
                        reason="ip_filter")
        hits = ai_batch.analyze_false_positive()
        assert not any(d == "cdn-hosting.com" for d, _, _ in hits)

    def test_run_analysis_includes_fp(self, fp_env):
        _add_intercepts("office-partner.com", clients=6, hits_each=3)
        with db_cursor() as cur:
            cur.execute("INSERT OR IGNORE INTO domain_first_seen "
                        "(domain, first_client, qtype) VALUES (?,?,?)",
                        ("office-partner.com", "10.0.0.1", "A"))
        stats = ai_batch.run_analysis()
        assert stats["fp_found"] >= 1
        assert stats["fp_new"] >= 1
        with db_cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM ai_findings "
                        "WHERE type='false_positive'")
            assert cur.fetchone()["n"] >= 1


# ---------------------------------------------------------------------------
# 5/6. API
# ---------------------------------------------------------------------------


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
    return r.json()["data"]["token"]


def _h(token):
    return {"Authorization": f"Bearer {token}"}


class TestApi:
    def test_list_view(self, client, token, fp_env):
        _add_intercepts("github.com", clients=8, hits_each=4)
        ai_batch.run_analysis()
        r = client.get("/api/ai/false-positive", headers=_h(token))
        items = r.json()["data"]["items"]
        assert any(i["target"] == "github.com" for i in items)
        assert all("already_whitelisted" in i for i in items)

    def test_whitelist_confirm_flow(self, client, token, fp_env):
        _add_intercepts("github.com", clients=8, hits_each=4)
        ai_batch.run_analysis()
        r = client.post("/api/ai/false-positive/github.com/whitelist",
                        params={"remark": "开发必需"}, headers=_h(token))
        assert r.status_code == 200
        # 白名单已写入
        with db_cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS n FROM filter_list WHERE list_type='whitelist'"
                " AND target='domain' AND value='github.com'")
            assert cur.fetchone()["n"] == 1
            # 结论已标记 confirmed
            cur.execute("SELECT status FROM ai_findings "
                        "WHERE type='false_positive' AND target='github.com'")
            assert cur.fetchone()["status"] == "confirmed"
            # 审计留痕
            cur.execute("SELECT COUNT(*) AS n FROM audit_log "
                        "WHERE action='ai_false_positive_whitelist'")
            assert cur.fetchone()["n"] >= 1
        # 重复加白 → 409
        r2 = client.post("/api/ai/false-positive/github.com/whitelist",
                         headers=_h(token))
        assert r2.status_code == 409
        with db_cursor() as cur:
            cur.execute("DELETE FROM filter_list WHERE value='github.com'"
                        " AND list_type='whitelist'")
        invalidate_list_cache()

    def test_invalid_domain_400(self, client, token):
        r = client.post("/api/ai/false-positive/localhost/whitelist",
                        headers=_h(token))
        assert r.status_code == 400
