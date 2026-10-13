"""AI 批处理器测试（迭代 49 · AI 能力规划 P0-4）。

覆盖：
  1. DGA 分析：首现表里的 DGA 域名 → ai_findings(dga_suspect)；
  2. 隧道分析：（客户端, 父域）聚合达门槛且特征明显 → ai_findings(tunnel_suspect)；
  3. 幂等：重复运行不产生重复行（更新既有 pending）；
  4. 正常域名零结论（降噪）；
  5. 窗口过滤：超出窗口的旧首现不参与分析；
  6. findings_summary 概览。

运行：cd platform && python -m pytest ../tests/test_ai_batch.py -v
"""

import random
import string

import pytest

import ai_batch
from config import CONFIG
from app.db import db_cursor


@pytest.fixture
def ab_env():
    """清空首现表与结论表，还原配置。"""
    with db_cursor() as cur:
        cur.execute("DELETE FROM domain_first_seen")
        cur.execute("DELETE FROM ai_findings")
    yield
    with db_cursor() as cur:
        cur.execute("DELETE FROM domain_first_seen")
        cur.execute("DELETE FROM ai_findings")


def _add_first_seen(rows):
    """rows: [(domain, client, qtype, hours_ago)]"""
    with db_cursor() as cur:
        for domain, client, qtype, ago in rows:
            cur.execute(
                """INSERT OR REPLACE INTO domain_first_seen
                   (domain, first_client, qtype, first_seen)
                   VALUES (?, ?, ?, datetime('now','localtime', ?))""",
                (domain, client, qtype, f"-{ago} hours"))


class TestRunAnalysis:
    def test_dga_detected(self, ab_env):
        _add_first_seen([
            ("xj3k9d2mz7qp.icu", "10.0.0.1", "A", 1),
            ("fwjvbqkzxmnrpl.shop", "10.0.0.2", "A", 2),
        ])
        stats = ai_batch.run_analysis(window_hours=24)
        assert stats["dga_found"] == 2
        with db_cursor() as cur:
            cur.execute("SELECT target, score FROM ai_findings "
                        "WHERE type='dga_suspect' ORDER BY target")
            rows = cur.fetchall()
        assert len(rows) == 2
        assert all(r["score"] >= 0.5 for r in rows)

    def test_idempotent_no_duplicates(self, ab_env):
        _add_first_seen([("xj3k9d2mz7qp.icu", "10.0.0.1", "A", 1)])
        s1 = ai_batch.run_analysis()
        s2 = ai_batch.run_analysis()
        assert s1["dga_new"] == 1
        assert s2["dga_new"] == 0            # 第二次为更新，不新建
        with db_cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM ai_findings "
                        "WHERE type='dga_suspect'")
            assert cur.fetchone()["n"] == 1

    def test_normal_domains_no_finding(self, ab_env):
        _add_first_seen([
            ("www.example.com", "10.0.0.1", "A", 1),
            ("mail.google.com", "10.0.0.2", "A", 1),
            ("static.cdn.taobao.com", "10.0.0.3", "A", 1),
        ])
        stats = ai_batch.run_analysis()
        assert stats["dga_found"] == 0
        with db_cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM ai_findings")
            assert cur.fetchone()["n"] == 0

    def test_tunnel_detected(self, ab_env):
        """同一客户端对同一父域的大量长随机子域（首现）→ 隧道结论。"""
        random.seed(5)
        rows = []
        for i in range(30):
            sub = "".join(random.choices(string.ascii_lowercase + string.digits,
                                         k=42))
            rows.append((f"{sub}.evil-c2.com", "10.9.9.9", "TXT", 1))
        _add_first_seen(rows)
        stats = ai_batch.run_analysis()
        assert stats["tunnel_found"] >= 1
        with db_cursor() as cur:
            cur.execute("SELECT target, score, evidence FROM ai_findings "
                        "WHERE type='tunnel_suspect'")
            r = cur.fetchone()
        assert r is not None
        assert "evil-c2.com" in r["target"]
        assert "10.9.9.9" in r["target"]
        assert r["score"] >= 0.6

    def test_tunnel_below_min_subdomains_skipped(self, ab_env):
        """子域数不足门槛不评分（降噪）——5 个子域不应产生隧道结论。"""
        random.seed(6)
        rows = []
        for i in range(5):
            sub = "".join(random.choices(string.ascii_lowercase, k=40))
            rows.append((f"{sub}.evil-c3.com", "10.8.8.8", "TXT", 1))
        _add_first_seen(rows)
        stats = ai_batch.run_analysis()
        assert stats["tunnel_found"] == 0

    def test_window_filter(self, ab_env):
        """窗口外的旧首现不参与分析。"""
        _add_first_seen([("xj3k9d2mz7qp.icu", "10.0.0.1", "A", 72)])  # 3 天前
        stats = ai_batch.run_analysis(window_hours=24)
        assert stats["dga_scanned"] == 0
        assert stats["dga_found"] == 0

    def test_summary(self, ab_env):
        _add_first_seen([("xj3k9d2mz7qp.icu", "10.0.0.1", "A", 1)])
        ai_batch.run_analysis()
        s = ai_batch.findings_summary()
        assert s.get("dga_suspect") == 1
