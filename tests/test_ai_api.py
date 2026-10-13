"""AI 旁路分析接口测试（迭代 49 · AI 能力规划 P0-5）。

覆盖：
  1. /api/ai/findings 空态与过滤（type/status/min_score/分页）；
  2. /api/ai/dga-suspects 与 /api/ai/tunnel-suspects 便捷视图；
  3. /api/ai/findings/{id}/status 确认/忽略 + 审计留痕 + 非法状态 400；
  4. /api/ai/stats 概览结构（首现规模、结论统计、采集/批处理状态）；
  5. 未授权访问 401。

运行：cd platform && python -m pytest ../tests/test_ai_api.py -v
"""

import json

import pytest
from fastapi.testclient import TestClient

from app.main import app
from config import CONFIG
from app.db import db_cursor


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


def _h(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def clean_ai_tables():
    with db_cursor() as cur:
        cur.execute("DELETE FROM ai_findings")
        cur.execute("DELETE FROM domain_first_seen")
    yield
    with db_cursor() as cur:
        cur.execute("DELETE FROM ai_findings")
        cur.execute("DELETE FROM domain_first_seen")


def _seed_finding(ftype="dga_suspect", target="xj3k9d2mz7qp.icu",
                  score=0.72, status="pending"):
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO ai_findings (type, target, score, evidence, status) "
            "VALUES (?, ?, ?, ?, ?)",
            (ftype, target, score,
             json.dumps({"label": "xj3k9d2mz7qp", "entropy": 3.6}),
             status))
        return cur.lastrowid


class TestFindings:
    def test_empty(self, client, token):
        r = client.get("/api/ai/findings", headers=_h(token))
        assert r.status_code == 200
        d = r.json()["data"]
        assert d["total"] == 0 and d["items"] == []

    def test_list_and_evidence_parsed(self, client, token):
        _seed_finding()
        r = client.get("/api/ai/findings", headers=_h(token))
        d = r.json()["data"]
        assert d["total"] == 1
        it = d["items"][0]
        assert it["target"] == "xj3k9d2mz7qp.icu"
        assert isinstance(it["evidence"], dict)        # JSON 已解析
        assert it["evidence"]["entropy"] == 3.6

    def test_filter_by_type_and_score(self, client, token):
        _seed_finding("dga_suspect", "a.icu", 0.60)
        _seed_finding("tunnel_suspect", "10.0.0.1|evil.com", 0.90)
        r = client.get("/api/ai/findings", params={"type": "tunnel_suspect"},
                       headers=_h(token))
        assert r.json()["data"]["total"] == 1
        r = client.get("/api/ai/findings", params={"min_score": 0.8},
                       headers=_h(token))
        assert r.json()["data"]["total"] == 1

    def test_filter_by_status(self, client, token):
        _seed_finding(status="pending")
        _seed_finding(target="b.icu", status="confirmed")
        r = client.get("/api/ai/findings", params={"status": "confirmed"},
                       headers=_h(token))
        assert r.json()["data"]["total"] == 1

    def test_invalid_type_400(self, client, token):
        r = client.get("/api/ai/findings", params={"type": "bogus"},
                       headers=_h(token))
        assert r.status_code == 400

    def test_dga_view(self, client, token):
        _seed_finding("dga_suspect", "xj3k9d2mz7qp.icu", 0.72)
        _seed_finding("tunnel_suspect", "10.0.0.1|evil.com", 0.9)
        r = client.get("/api/ai/dga-suspects", headers=_h(token))
        items = r.json()["data"]["items"]
        assert len(items) == 1
        assert items[0]["type"] == "dga_suspect"

    def test_tunnel_view(self, client, token):
        _seed_finding("tunnel_suspect", "10.0.0.1|evil.com", 0.9)
        r = client.get("/api/ai/tunnel-suspects", headers=_h(token))
        items = r.json()["data"]["items"]
        assert len(items) == 1
        assert "evil.com" in items[0]["target"]


class TestStatusUpdate:
    def test_confirm_and_audit(self, client, token):
        fid = _seed_finding()
        r = client.post(f"/api/ai/findings/{fid}/status",
                        params={"status": "confirmed"}, headers=_h(token))
        assert r.status_code == 200
        assert r.json()["data"]["status"] == "confirmed"
        with db_cursor() as cur:
            cur.execute("SELECT status FROM ai_findings WHERE id=?", (fid,))
            assert cur.fetchone()["status"] == "confirmed"
            cur.execute("SELECT COUNT(*) AS n FROM audit_log "
                        "WHERE action='ai_finding_status'")
            assert cur.fetchone()["n"] >= 1        # 审计留痕

    def test_invalid_status_400(self, client, token):
        fid = _seed_finding()
        r = client.post(f"/api/ai/findings/{fid}/status",
                        params={"status": "pending"}, headers=_h(token))
        assert r.status_code == 400

    def test_missing_finding_404(self, client, token):
        r = client.post("/api/ai/findings/999999/status",
                        params={"status": "confirmed"}, headers=_h(token))
        assert r.status_code == 404


class TestStats:
    def test_stats_shape(self, client, token):
        with db_cursor() as cur:
            cur.execute("INSERT OR IGNORE INTO domain_first_seen "
                        "(domain, first_client, qtype) VALUES (?,?,?)",
                        ("stats-test.com", "10.0.0.1", "A"))
        _seed_finding()
        r = client.get("/api/ai/stats", headers=_h(token))
        assert r.status_code == 200
        d = r.json()["data"]
        assert d["first_seen_total"] >= 1
        assert "dga_suspect" in d["findings"]
        assert "collector" in d and "batch" in d
        assert "enqueued" in d["collector"]


class TestAuth:
    def test_unauthorized(self, client):
        assert client.get("/api/ai/findings").status_code == 401
        assert client.get("/api/ai/stats").status_code == 401
