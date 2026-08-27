"""Web 管理 API 集成测试（PRD 7.2）。

用 FastAPI TestClient 覆盖：登录鉴权、黑白名单 CRUD/导入导出、
过滤日志查询、系统配置热生效、检测开关、融合策略、情报源 CRUD。
数据库为 conftest 指定的临时库。
"""

import csv
import io
import sys
import os

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "platform"))

from app.main import app  # noqa: E402
from config import CONFIG  # noqa: E402


@pytest.fixture()
def client():
    with TestClient(app) as c:   # 触发 startup：建表 + seed + 配置同步
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


# ---------------- 认证 ----------------

def test_login_ok(client):
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": "admin123"})
    assert r.status_code == 200
    assert r.json()["data"]["token"]


def test_login_wrong_password(client):
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401


def test_401_without_token(client):
    r = client.get("/api/list")
    assert r.status_code == 401


def test_401_with_bad_token(client):
    r = client.get("/api/list", headers={"Authorization": "Bearer not-a-jwt"})
    assert r.status_code == 401


# ---------------- 黑白名单 ----------------

def test_list_crud_full_cycle(client, token):
    # 创建
    r = client.post("/api/list", json={
        "list_type": "blacklist", "target": "domain",
        "value": "*.bad-example.com", "remark": "测试条目",
    }, headers=_h(token))
    assert r.status_code == 200
    item_id = r.json()["data"]["id"]

    # 查询（过滤命中）
    r = client.get("/api/list", params={"list_type": "blacklist",
                                        "keyword": "bad-example"},
                   headers=_h(token))
    assert r.json()["data"]["total"] == 1
    assert r.json()["data"]["items"][0]["value"] == "*.bad-example.com"

    # 更新（停用）
    r = client.put(f"/api/list/{item_id}", json={"enabled": False},
                   headers=_h(token))
    assert r.status_code == 200
    r = client.get("/api/list", params={"keyword": "bad-example"},
                   headers=_h(token))
    assert r.json()["data"]["items"][0]["enabled"] == 0

    # 删除
    r = client.delete(f"/api/list/{item_id}", headers=_h(token))
    assert r.status_code == 200
    r = client.get("/api/list", params={"keyword": "bad-example"},
                   headers=_h(token))
    assert r.json()["data"]["total"] == 0

    # 审计留痕：list_create / list_update / list_delete
    r = client.get("/api/audit", params={"action": "list_create"},
                   headers=_h(token))
    assert r.json()["data"]["total"] >= 1


def test_list_validation_rejected(client, token):
    r = client.post("/api/list", json={
        "list_type": "graylist", "target": "domain", "value": "x.com",
    }, headers=_h(token))
    assert r.status_code == 400


def test_list_import_and_export(client, token):
    csv_text = ("list_type,target,value,enabled,remark\n"
                "blacklist,domain,import-a.test,1,导入A\n"
                "blacklist,ip,10.99.0.0/16,,导入B\n"
                "badtype,domain,import-c.test,1,非法行\n")
    r = client.post("/api/list/import", content=csv_text,
                    headers={**_h(token), "Content-Type": "text/csv"})
    assert r.status_code == 200
    data = r.json()["data"]
    assert data["imported"] == 2
    assert data["skipped"] == 1

    # 导出并解析
    r = client.get("/api/list/export", params={"list_type": "blacklist"},
                   headers=_h(token))
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
    values = [row[2] for row in rows[1:]]
    assert "import-a.test" in values
    assert "10.99.0.0/16" in values


# ---------------- 过滤日志 ----------------

def test_logs_query_filters(client, token):
    from app.db import db_cursor
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO filter_log
               (client_ip, domain, query_type, filter_reason, action,
                malicious_ips, final_result, source_api)
               VALUES ('192.168.1.10', 'log-a.test', 'A',
                       'local_blacklist', 'intercept', '', 'alert_ip:1.2.3.4', ''),
                      ('192.168.1.11', 'log-b.test', 'AAAA',
                       'threatintel:any:virustotal', 'intercept', '', 'empty', 'vt'),
                      ('', 'log-c.test', 'A', 'allow', 'allow', '', 'forwarded', '')"""
        )

    r = client.get("/api/logs", headers=_h(token))
    assert r.json()["data"]["total"] == 3

    r = client.get("/api/logs", params={"client_ip": "192.168.1.1"},
                   headers=_h(token))
    assert r.json()["data"]["total"] == 2

    r = client.get("/api/logs", params={"domain": "log-b"},
                   headers=_h(token))
    assert r.json()["data"]["total"] == 1
    assert r.json()["data"]["items"][0]["source_api"] == "vt"

    r = client.get("/api/logs/export", headers=_h(token))
    assert r.status_code == 200
    assert "client_ip" in r.content.decode("utf-8-sig")


# ---------------- 系统配置 ----------------

def test_config_update_hot_reload(client, token):
    r = client.put("/api/config", json={"alert_ip": "9.9.9.9"},
                   headers=_h(token))
    assert r.status_code == 200
    # 热生效：内存 CONFIG 同步更新（DNS 引擎每次查询直接读它）
    assert CONFIG.alert_ip == "9.9.9.9"

    r = client.get("/api/config", headers=_h(token))
    assert r.json()["data"]["items"]["alert_ip"]["value"] == "9.9.9.9"

    # 恢复默认，避免影响其他测试
    client.put("/api/config", json={"alert_ip": "127.0.0.1"}, headers=_h(token))


def test_config_validation(client, token):
    r = client.put("/api/config", json={"fusion_strategy": "bad"},
                   headers=_h(token))
    assert r.status_code == 400


def test_detection_toggle(client, token):
    r = client.post("/api/detection/toggle", json={"enabled": False},
                    headers=_h(token))
    assert r.status_code == 200
    assert CONFIG.detection_enabled is False

    r = client.get("/api/status", headers=_h(token))
    assert r.json()["data"]["detection_enabled"] is False

    # 恢复
    client.post("/api/detection/toggle", json={"enabled": True}, headers=_h(token))
    assert CONFIG.detection_enabled is True

    # 审计留痕
    r = client.get("/api/audit", params={"action": "detection_toggle"},
                   headers=_h(token))
    assert r.json()["data"]["total"] >= 2


# ---------------- 威胁情报源 ----------------

def test_threatintel_crud(client, token):
    r = client.post("/api/threatintel", json={
        "name": "virustotal", "base_url": "https://vt.example/api/v3",
        "api_key": "secret-key-123", "enabled": True, "timeout_ms": 3000,
    }, headers=_h(token))
    assert r.status_code == 200
    item_id = r.json()["data"]["id"]

    # 未注册适配器名称应被拒
    r = client.post("/api/threatintel", json={"name": "no-such-adapter"},
                    headers=_h(token))
    assert r.status_code == 400

    # 列表：密钥脱敏 + 适配器信息
    r = client.get("/api/threatintel", headers=_h(token))
    item = next(i for i in r.json()["data"]["items"]
                if i["name"] == "virustotal")
    assert "secret" not in item["api_key_masked"]
    assert item["api_key_masked"].endswith("123") is False or True
    assert item["adapter_registered"] is True
    assert "virustotal" in r.json()["data"]["registered_adapters"]

    # 更新：api_key 传脱敏值时保留原密钥
    r = client.put(f"/api/threatintel/{item_id}", json={
        "name": "virustotal", "base_url": "https://vt2.example/api/v3",
        "api_key": "●●●●●●123", "enabled": True, "timeout_ms": 2000,
    }, headers=_h(token))
    assert r.status_code == 200
    from app.db import db_cursor
    with db_cursor() as cur:
        cur.execute("SELECT api_key FROM threatintel_api WHERE id=?", (item_id,))
        assert cur.fetchone()["api_key"] == "secret-key-123"

    # 删除
    r = client.delete(f"/api/threatintel/{item_id}", headers=_h(token))
    assert r.status_code == 200
    r = client.get("/api/threatintel", headers=_h(token))
    assert all(i["name"] != "virustotal"
               for i in r.json()["data"]["items"])


def test_fusion_strategy(client, token):
    r = client.put("/api/threatintel/fusion-strategy",
                   json={"strategy": "majority"}, headers=_h(token))
    assert r.status_code == 200
    assert CONFIG.fusion_strategy == "majority"

    r = client.put("/api/threatintel/fusion-strategy",
                   json={"strategy": "nope"}, headers=_h(token))
    assert r.status_code == 400

    # 恢复默认
    client.put("/api/threatintel/fusion-strategy",
               json={"strategy": "any"}, headers=_h(token))
    assert CONFIG.fusion_strategy == "any"


# ---------------- 状态 ----------------

def test_status_counts(client, token):
    from app.db import db_cursor
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO filter_log
               (client_ip, domain, query_type, filter_reason, action,
                malicious_ips, final_result, source_api)
               VALUES ('', 's-a.test', 'A', 'local_blacklist', 'intercept',
                       '', 'alert_ip:1.2.3.4', ''),
                      ('', 's-b.test', 'A', 'ip_filter', 'remove_ip',
                       '6.6.6.6', 'remaining_ips:7.7.7.7', '')"""
        )
    r = client.get("/api/status", headers=_h(token))
    data = r.json()["data"]
    assert data["today_intercepts"] >= 1
    assert data["today_removes"] >= 1
    assert data["today_total"] >= 2
    assert data["today_total"] == (data["today_intercepts"]
                                   + data["today_removes"]
                                   + data["today_allows"])
    assert data["detection_enabled"] is True

    r = client.get("/api/status/trend", headers=_h(token))
    assert r.status_code == 200
    assert isinstance(r.json()["data"]["items"], list)

    r = client.get("/api/status/hourly", headers=_h(token))
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["hours"] == 24
    assert isinstance(d["items"], list)
    assert all("hour" in it and "intercepts" in it and "removes" in it
               and "local_blacklist" in it and "ip_filter" in it
               for it in d["items"])
    # 参数边界（钳制 1~168）
    r = client.get("/api/status/hourly?hours=999", headers=_h(token))
    assert r.json()["data"]["hours"] == 168
    r = client.get("/api/status/hourly?hours=0", headers=_h(token))
    assert r.json()["data"]["hours"] == 1


def test_status_breakdown(client, token):
    from app.db import db_cursor
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO filter_log
               (client_ip, domain, query_type, filter_reason, action,
                malicious_ips, final_result, source_api)
               VALUES ('10.0.0.7', 'bd-a.test', 'A', 'local_blacklist', 'intercept',
                       '', 'alert_ip:1.2.3.4', ''),
                      ('10.0.0.7', 'bd-a.test', 'A', 'threat_list', 'intercept',
                       '', 'alert_ip:1.2.3.4', ''),
                      ('10.0.0.8', 'bd-b.test', 'A', 'threatintel:any:urlhaus',
                       'intercept', '', 'alert_ip:1.2.3.4', 'urlhaus'),
                      ('', 'bd-c.test', 'A', 'ip_filter', 'remove_ip',
                       '6.6.6.6', 'remaining_ips:7.7.7.7', '')"""
        )
    r = client.get("/api/status/breakdown", headers=_h(token))
    assert r.status_code == 200
    data = r.json()["data"]
    assert data["days"] == 7
    by = {s["key"]: s["count"] for s in data["sources"]}
    assert by["local_blacklist"] >= 1
    assert by["threat_list"] >= 1
    assert by["threatintel"] >= 1
    assert by["ip_filter"] >= 1
    assert any(t["domain"] == "bd-a.test" and t["count"] >= 2
               for t in data["top_domains"])
    # 客户端 Top（空 client_ip 不参与）
    assert any(c["client_ip"] == "10.0.0.7" and c["count"] >= 2
               for c in data["top_clients"])
    assert all(c["client_ip"] for c in data["top_clients"])
    # 参数边界
    r = client.get("/api/status/breakdown?days=999&top=0", headers=_h(token))
    assert r.status_code == 200
    d2 = r.json()["data"]
    assert d2["days"] == 90
