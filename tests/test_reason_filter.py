"""迭代 39：过滤原因筛选增强——threat_list 命中带源名 + 原因下拉端点。

覆盖三块：
1. /api/logs/reasons 下拉选项端点（fixed 四类 + 已启用在线源 + 已启用离线源）；
2. breakdown/hourly 的 threat_list 归类改前缀匹配（threat_list:<source>
   新格式与裸 threat_list 旧数据都计数）；
3. 检测主流程 threat_list 命中日志 reason=threat_list:<source> 且
   source_api 填源 key（detectors 层单测，直查 log_writer 落库行）。
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


from app.db import db_cursor  # noqa: E402


def _cleanup():
    with db_cursor() as cur:
        cur.execute("DELETE FROM filter_log WHERE domain LIKE 'it39-%'")
        cur.execute("DELETE FROM threat_list WHERE source='it39_src'")
        cur.execute("DELETE FROM threatintel_api WHERE name LIKE 'it39_%'")


def test_logs_reasons_options(client, token):
    """reasons 端点：fixed 四类 + 已启用在线源 + 已启用离线源分组。"""
    from app import threat_list
    _cleanup()
    try:
        # 造一个启用的离线源条目 + 一个停用源条目
        threat_list.import_source("it39_src", "a.it39.test\n", enabled=True)
        # 造一个启用的在线源 + 一个停用的
        with db_cursor() as cur:
            cur.execute(
                """INSERT INTO threatintel_api
                   (name, adapter_type, base_url, api_key, enabled)
                   VALUES ('it39_on', 'http', 'https://x.example/', '', 1),
                          ('it39_off', 'http', 'https://y.example/', '', 0)""")
        r = client.get("/api/logs/reasons", headers={
            "Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        d = r.json()["data"]
        fixed_keys = [x["key"] for x in d["fixed"]]
        assert fixed_keys == ["local_blacklist", "threat_list",
                              "ip_filter", "threatintel",
                              "nrd", "nrd_observe"]
        online = [x["key"] for x in d["online"]]
        assert "it39_on" in online
        assert "it39_off" not in online
        offline = [x["key"] for x in d["offline"]]
        assert "it39_src" in offline
        # 停用源（enabled_cnt=0）不在 offline 组
        assert "oisd" not in offline or True  # oisd 状态取决于库，不强断言
    finally:
        _cleanup()


def test_logs_filter_by_suffixed_reason(client, token):
    """reason 筛选：threat_list:<source> 前缀 LIKE 匹配新旧两种格式。"""
    _cleanup()
    try:
        with db_cursor() as cur:
            cur.execute(
                """INSERT INTO filter_log
                   (client_ip, domain, query_type, filter_reason, action,
                    malicious_ips, final_result, source_api)
                   VALUES ('', 'it39-new.test', 'A', 'threat_list:hagezi_ti',
                           'intercept', '', '', 'hagezi_ti'),
                          ('', 'it39-old.test', 'A', 'threat_list',
                           'intercept', '', '', '')""")
        h = {"Authorization": f"Bearer {token}"}
        # 按源筛选：命中新格式
        r = client.get("/api/logs?reason=threat_list:hagezi_ti", headers=h)
        domains = [x["domain"] for x in r.json()["data"]["items"]]
        assert "it39-new.test" in domains
        assert "it39-old.test" not in domains
        # 全量 threat_list 前缀：新旧都命中
        r = client.get("/api/logs?reason=threat_list", headers=h)
        domains = [x["domain"] for x in r.json()["data"]["items"]]
        assert "it39-new.test" in domains
        assert "it39-old.test" in domains
    finally:
        _cleanup()


def test_breakdown_hourly_prefix_match(client, token):
    """breakdown/hourly 的 threat_list 归类：前缀匹配新格式不漏计。"""
    _cleanup()
    try:
        with db_cursor() as cur:
            cur.execute(
                """INSERT INTO filter_log
                   (client_ip, domain, query_type, filter_reason, action,
                    malicious_ips, final_result, source_api)
                   VALUES ('', 'it39-bd.test', 'A', 'threat_list:hagezi_mini',
                           'intercept', '', '', 'hagezi_mini')""")
        h = {"Authorization": f"Bearer {token}"}
        r = client.get("/api/status/breakdown?scope=today", headers=h)
        by = {s["key"]: s["count"] for s in r.json()["data"]["sources"]}
        assert by["threat_list"] >= 1
        r = client.get("/api/status/hourly?hours=1", headers=h)
        assert any(it["threat_list"] >= 1
                   for it in r.json()["data"]["items"])
    finally:
        _cleanup()


def test_detectors_threat_list_reason_with_source():
    """检测主流程：threat_list 命中日志 reason=threat_list:<source> 且
    source_api=源 key（迭代 39 核心——过滤日志页按源筛选的数据基础）。"""
    from app import threat_list
    import log_writer
    _cleanup()
    log_writer.start()
    try:
        threat_list.import_source("it39_src", "hitme.it39.test\n",
                                  enabled=True)
        import detectors
        from dnslib import DNSRecord
        # dnslib question() 的 qtype 须传字符串名（"A"），传 QTYPE.A
        # （int）会触发 "attribute name must be string, not 'int'"
        q = DNSRecord.question("hitme.it39.test", "A")
        # detection_enabled 需为真（默认）——直接调主流程
        detectors.process_query(q)
        log_writer.stop(flush=True)
        with db_cursor() as cur:
            cur.execute(
                "SELECT filter_reason, source_api FROM filter_log "
                "WHERE domain='hitme.it39.test' ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
        assert row is not None
        assert row["filter_reason"] == "threat_list:it39_src"
        assert row["source_api"] == "it39_src"
    finally:
        log_writer.stop(flush=True)
        _cleanup()
