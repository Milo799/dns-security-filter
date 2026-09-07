"""域名分析聚合端点测试（迭代 37：GET /api/logs/agg/domains）。

覆盖：基础聚合正确性（计数/首末次时间）、排序（总次数降序）、
动作过滤、域名模糊过滤、时间窗过滤、reason_top 构成、分页、
认证（401）、空库空窗返回空。
"""

import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "platform"))

from app.main import app  # noqa: E402
from config import CONFIG  # noqa: E402


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


def _seed(rows):
    """直插 filter_log 测试数据。rows: (domain, reason, action, ts)。"""
    from app.db import db_cursor
    with db_cursor() as cur:
        cur.execute("DELETE FROM filter_log")
        for domain, reason, action, ts in rows:
            cur.execute(
                """INSERT INTO filter_log
                   (client_ip, domain, query_type, filter_reason, action,
                    malicious_ips, final_result, source_api, timestamp)
                   VALUES ('', ?, 'A', ?, ?, '', '', '', ?)""",
                (domain, reason, action, ts),
            )


@pytest.fixture(autouse=True)
def _cleanup_filter_log():
    """退出时清空 filter_log：共享临时库防跨文件数据污染
    （字母序下 test_agg_* 先于 test_api_* 运行，残留会串扰其计数断言）。"""
    yield
    from app.db import db_cursor
    with db_cursor() as cur:
        cur.execute("DELETE FROM filter_log")


def test_agg_requires_auth(client):
    r = client.get("/api/logs/agg/domains")
    assert r.status_code == 401


def test_agg_empty_db(client, token):
    _seed([])          # 清空可能跨文件残留的 filter_log（共享临时库）
    r = client.get("/api/logs/agg/domains", headers=_h(token))
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["total"] == 0
    assert d["items"] == []


def test_agg_basic_counts_and_order(client, token):
    _seed([
        # a.test 拦 3 + 放 1 = 4（第一名）
        ("a.test", "local_blacklist", "intercept", "2026-09-07 10:00:00"),
        ("a.test", "local_blacklist", "intercept", "2026-09-07 10:00:05"),
        ("a.test", "threat_list", "intercept", "2026-09-07 10:00:10"),
        ("a.test", "", "allow", "2026-09-07 10:00:15"),
        # b.test 拦 2（第二名）
        ("b.test", "threat_list", "intercept", "2026-09-07 11:00:00"),
        ("b.test", "ip_filter", "remove_ip", "2026-09-07 11:00:30"),
    ])
    r = client.get("/api/logs/agg/domains", headers=_h(token))
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["total"] == 2
    assert len(d["items"]) == 2

    top = d["items"][0]
    assert top["domain"] == "a.test"
    assert top["total"] == 4
    assert top["intercepts"] == 3
    assert top["removes"] == 0
    assert top["allows"] == 1
    assert top["first_seen"] == "2026-09-07 10:00:00"
    assert top["last_seen"] == "2026-09-07 10:00:15"

    second = d["items"][1]
    assert second["domain"] == "b.test"
    assert second["total"] == 2
    assert second["removes"] == 1


def test_agg_reason_top(client, token):
    _seed([
        ("a.test", "threat_list", "intercept", "2026-09-07 10:00:00"),
        ("a.test", "threat_list", "intercept", "2026-09-07 10:00:05"),
        ("a.test", "local_blacklist", "intercept", "2026-09-07 10:00:10"),
    ])
    r = client.get("/api/logs/agg/domains", headers=_h(token))
    top = r.json()["data"]["items"][0]
    reasons = top["reason_top"]
    assert len(reasons) == 2
    # 计数高的在前
    assert reasons[0]["reason"] == "threat_list"
    assert reasons[0]["count"] == 2
    assert reasons[1]["reason"] == "local_blacklist"
    assert reasons[1]["count"] == 1


def test_agg_reason_top_capped_at_3(client, token):
    _seed([
        ("a.test", f"threatintel:any:src{i}", "intercept",
         f"2026-09-07 10:00:0{i}")
        for i in range(5)
    ] + [
        ("a.test", "threat_list", "intercept", "2026-09-07 10:01:00"),
    ] * 2)
    r = client.get("/api/logs/agg/domains", headers=_h(token))
    top = r.json()["data"]["items"][0]
    assert len(top["reason_top"]) == 3          # 最多 3 个
    assert top["reason_top"][0]["reason"] == "threat_list"  # 计数 2 领先


def test_agg_action_filter(client, token):
    _seed([
        ("a.test", "local_blacklist", "intercept", "2026-09-07 10:00:00"),
        ("b.test", "", "allow", "2026-09-07 10:00:01"),
    ])
    r = client.get("/api/logs/agg/domains?action=allow",
                   headers=_h(token))
    d = r.json()["data"]
    assert d["total"] == 1
    assert d["items"][0]["domain"] == "b.test"

    r = client.get("/api/logs/agg/domains?action=intercept",
                   headers=_h(token))
    d = r.json()["data"]
    assert d["total"] == 1
    assert d["items"][0]["domain"] == "a.test"


def test_agg_domain_fuzzy_filter(client, token):
    _seed([
        ("ads.example.com", "threat_list", "intercept", "2026-09-07 10:00:00"),
        ("ntp.aliyun.com", "threat_list", "intercept", "2026-09-07 10:00:01"),
    ])
    r = client.get("/api/logs/agg/domains?domain=aliyun",
                   headers=_h(token))
    d = r.json()["data"]
    assert d["total"] == 1
    assert d["items"][0]["domain"] == "ntp.aliyun.com"


def test_agg_time_window(client, token):
    _seed([
        ("a.test", "local_blacklist", "intercept", "2026-09-06 23:00:00"),
        ("a.test", "local_blacklist", "intercept", "2026-09-07 10:00:00"),
        ("b.test", "local_blacklist", "intercept", "2026-09-07 10:00:01"),
    ])
    # 只看 09-07 窗口：a.test 仅剩 1 条
    r = client.get("/api/logs/agg/domains"
                   "?start=2026-09-07 00:00:00&end=2026-09-07 23:59:59",
                   headers=_h(token))
    d = r.json()["data"]
    assert d["total"] == 2
    a = next(it for it in d["items"] if it["domain"] == "a.test")
    assert a["total"] == 1
    assert a["first_seen"] == "2026-09-07 10:00:00"


def test_agg_pagination(client, token):
    _seed([
        (f"d{i:02d}.test", "threat_list", "intercept",
         f"2026-09-07 10:00:{i:02d}")
        for i in range(25)
    ])
    r = client.get("/api/logs/agg/domains?size=10&page=1",
                   headers=_h(token))
    d = r.json()["data"]
    assert d["total"] == 25
    assert len(d["items"]) == 10
    assert d["items"][0]["domain"] == "d00.test"

    r = client.get("/api/logs/agg/domains?size=10&page=3",
                   headers=_h(token))
    d = r.json()["data"]
    assert len(d["items"]) == 5            # 25 = 10+10+5


def test_agg_size_clamped(client, token):
    _seed([
        ("a.test", "threat_list", "intercept", "2026-09-07 10:00:00"),
    ])
    # size 超 100 被拒（FastAPI Query le 校验）
    r = client.get("/api/logs/agg/domains?size=1000",
                   headers=_h(token))
    assert r.status_code == 422
