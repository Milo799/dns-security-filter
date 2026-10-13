"""P2 测试：客户端行为基线 + 失陷主机识别 + 情报质量评分（迭代 49）。

覆盖：
  1. client_anomaly_score 区分度（异常主机高分 / 正常主机低分）；
  2. analyze_client_anomaly：大规模首现 + 高拦截 + 父域分散 → 检出；
     正常客户端（少量首现、无拦截）不检出；
  3. analyze_intel_quality：命中贡献归一评分 + 命中密度；
  4. API：/client-anomalies、/intel-quality；
  5. run_analysis 纳入 P2 两类结论。

运行：cd platform && python -m pytest ../tests/test_ai_p2.py -v
"""

import random
import string

import pytest
from fastapi.testclient import TestClient

import ai_analysis
import ai_batch
from app.main import app
from app.db import db_cursor
from config import CONFIG


# ---------------------------------------------------------------------------
# 1. 算法
# ---------------------------------------------------------------------------


class TestAnomalyScore:
    def test_compromised_host_scores_high(self):
        s, ev = ai_analysis.client_anomaly_score(
            new_domains=400, intercepts=35, parents=150, baseline_new=5.0)
        assert s >= ai_analysis.ANOMALY_THRESHOLD
        assert ev["new_domains"] == 400
        assert set(ev["contributions"]) == {"scale", "intercept", "parents"}

    def test_normal_host_scores_low(self):
        s, _ = ai_analysis.client_anomaly_score(
            new_domains=20, intercepts=1, parents=12, baseline_new=8.0)
        assert s < ai_analysis.ANOMALY_THRESHOLD

    def test_scale_relative_to_baseline(self):
        """相同新域名数，基线不同 → 评分不同（横截面语义）。"""
        s_low, _ = ai_analysis.client_anomaly_score(100, 5, 40, baseline_new=50.0)
        s_high, _ = ai_analysis.client_anomaly_score(100, 5, 40, baseline_new=2.0)
        assert s_high > s_low


# ---------------------------------------------------------------------------
# 2/3. 批处理
# ---------------------------------------------------------------------------


@pytest.fixture
def p2_env():
    """清空 AI 相关表 + threat_list（情报质量评分会读，且防污染后续测试）。

    threat_list 残留会让 enabled_source_keys 非空——test_auto_update 的
    空集断言与真实下载路径都会被打乱（全量套件顺序污染）。
    """
    with db_cursor() as cur:
        cur.execute("DELETE FROM domain_first_seen")
        cur.execute("DELETE FROM ai_findings")
        cur.execute("DELETE FROM filter_log")
        cur.execute("DELETE FROM threat_list")
    yield
    with db_cursor() as cur:
        cur.execute("DELETE FROM domain_first_seen")
        cur.execute("DELETE FROM ai_findings")
        cur.execute("DELETE FROM filter_log")
        cur.execute("DELETE FROM threat_list")


def _seed_hosts():
    """构造：1 台失陷嫌疑主机（大量首现+拦截+父域分散）+ 20 台正常主机。"""
    random.seed(13)
    with db_cursor() as cur:
        for i in range(120):
            sub = "".join(random.choices(string.ascii_lowercase, k=8))
            cur.execute(
                """INSERT OR IGNORE INTO domain_first_seen
                   (domain, first_client, qtype) VALUES (?,?,?)""",
                (f"{sub}.bad{i}.evil-{i}.com", "10.6.6.6", "A"))
        for i in range(30):
            cur.execute(
                """INSERT INTO filter_log
                   (client_ip, domain, query_type, filter_reason, action,
                    malicious_ips, final_result, source_api)
                   VALUES ('10.6.6.6', ?, 'A', 'threat_list:silverfox',
                           'intercept', '', 'alert_ip:127.0.0.1', 'silverfox')""",
                (f"hit{i}.evil-{i}.com",))
        # 20 台正常主机：各 5 个常用域
        for h in range(20):
            for k in range(5):
                cur.execute(
                    """INSERT OR IGNORE INTO domain_first_seen
                       (domain, first_client, qtype) VALUES (?,?,?)""",
                    (f"svc{k}.corp{h}.com", f"10.7.0.{h+1}", "A"))


class TestAnalyzeClients:
    def test_anomalous_host_detected(self, p2_env):
        _seed_hosts()
        hits = ai_batch.analyze_client_anomaly()
        ips = [h[0] for h in hits]
        assert "10.6.6.6" in ips
        score = [h[1] for h in hits if h[0] == "10.6.6.6"][0]
        assert score >= ai_analysis.ANOMALY_THRESHOLD

    def test_normal_hosts_not_flagged(self, p2_env):
        _seed_hosts()
        hits = ai_batch.analyze_client_anomaly()
        for ip, _, _ in hits:
            assert ip == "10.6.6.6", f"正常主机 {ip} 被误判"


class TestIntelQuality:
    def test_quality_by_hits(self, p2_env):
        with db_cursor() as cur:
            for i in range(20):
                cur.execute(
                    """INSERT INTO filter_log
                       (client_ip, domain, query_type, filter_reason, action,
                        malicious_ips, final_result, source_api)
                       VALUES ('10.9.0.1', ?, 'A', 'threat_list:silverfox',
                               'intercept', '', 'alert_ip:127.0.0.1', 'silverfox')""",
                    (f"d{i}.bad.com",))
            for i in range(3):
                cur.execute(
                    """INSERT INTO filter_log
                       (client_ip, domain, query_type, filter_reason, action,
                        malicious_ips, final_result, source_api)
                       VALUES ('10.9.0.1', ?, 'A', 'threat_list:hagezi_ti',
                               'intercept', '', 'alert_ip:127.0.0.1', 'hagezi_ti')""",
                    (f"h{i}.bad2.com",))
            cur.execute("INSERT OR IGNORE INTO threat_list (source, value, target)"
                        " VALUES ('silverfox','x.com','domain')")
        q = ai_batch.analyze_intel_quality()
        by = {x[0]: (x[1], x[2]) for x in q}
        assert "silverfox" in by and "hagezi_ti" in by
        assert by["silverfox"][0] > by["hagezi_ti"][0]   # 命中多者分高
        assert by["silverfox"][1]["hits"] == 20


class TestRunAnalysisP2:
    def test_results_included(self, p2_env):
        _seed_hosts()
        stats = ai_batch.run_analysis()
        assert stats["anomaly_found"] >= 1
        assert stats["quality_found"] >= 1
        with db_cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM ai_findings "
                        "WHERE type='client_anomaly'")
            assert cur.fetchone()["n"] >= 1


# ---------------------------------------------------------------------------
# 4. API
# ---------------------------------------------------------------------------


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def token(client):
    r = client.post("/api/auth/login", json={
        "username": "admin", "password": CONFIG.admin_initial_password})
    return r.json()["data"]["token"]


def _h(token):
    return {"Authorization": f"Bearer {token}"}


class TestApi:
    def test_client_anomalies_view(self, client, token, p2_env):
        _seed_hosts()
        ai_batch.run_analysis()
        r = client.get("/api/ai/client-anomalies", headers=_h(token))
        items = r.json()["data"]["items"]
        assert any(i["target"] == "10.6.6.6" for i in items)

    def test_intel_quality_view(self, client, token, p2_env):
        with db_cursor() as cur:
            cur.execute(
                """INSERT INTO filter_log
                   (client_ip, domain, query_type, filter_reason, action,
                    malicious_ips, final_result, source_api)
                   VALUES ('10.9.0.2','q.bad.com','A','threat_list:silverfox',
                           'intercept','','alert_ip:127.0.0.1','silverfox')""")
        ai_batch.run_analysis()
        r = client.get("/api/ai/intel-quality", headers=_h(token))
        assert r.status_code == 200
        items = r.json()["data"]["items"]
        assert any(i["target"] == "silverfox" for i in items)
        assert "hits" in items[0]["evidence"]
