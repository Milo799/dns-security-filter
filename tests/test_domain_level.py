"""人工名单域名层级防护测试 —— Task #176（迭代 29）。

背景：名单支持 *.xxx.com 通配（后缀匹配全部子域），*.com 这类
顶层通配在白名单=绕过全部检测、黑名单=全网瘫痪，都必须在入口拒绝。

覆盖：
  - domain_level 分级核心（PSL 感知：*.com / *.com.cn 拒绝，
    *.example.com 警示，子域/精确/多级后缀归类正确）
  - 创建/更新入口拒绝（400 + 明确文案）
  - 导入链路跳过顶层通配行并汇总原因
  - /api/list 层级筛选（tld/registrable/subdomain）与 wildcard 过滤
  - 存量脏数据展示口径（risk=blocked 标红，不炸接口）
"""

import pytest
from fastapi.testclient import TestClient


# ---------------- 分级核心（纯函数） ----------------

@pytest.mark.parametrize("value,level,wildcard,risk", [
    ("*.com", "tld", True, "blocked"),
    ("*.COM", "tld", True, "blocked"),          # 大小写归一
    ("*.com.cn", "tld", True, "blocked"),       # 多级公共后缀
    ("*.net.cn", "tld", True, "blocked"),
    ("*.co.uk", "tld", True, "blocked"),
    ("*.gov.cn", "tld", True, "blocked"),
    ("*", "", False, "blocked"),                # 裸星号
    ("*.", "", True, "blocked"),                # 空后缀笔误（*./前缀）
    ("*.example.com", "registrable", True, "warn"),   # 主域通配=警示
    ("*.example.com.cn", "registrable", True, "warn"),
    ("example.com", "registrable", False, ""),
    ("example.com.cn", "registrable", False, ""),
    ("a.example.com", "subdomain", False, ""),
    ("*.a.example.com", "subdomain", True, ""),       # 子域通配无警示
    ("b.example.com.cn", "subdomain", False, ""),
    ("com", "tld", False, ""),                  # 精确TLD不拦截但标层级
])
def test_classify_entry(value, level, wildcard, risk):
    from app.domain_level import classify_entry
    r = classify_entry("domain", value)
    assert r["level"] == level, f"{value}: {r}"
    assert r["wildcard"] == wildcard, f"{value}: {r}"
    assert r["risk"] == risk, f"{value}: {r}"
    if risk == "blocked":
        assert r["risk_note"], "blocked 必须带提示文案"


def test_classify_ip_passthrough():
    from app.domain_level import classify_entry
    r = classify_entry("ip", "10.0.0.0/8")
    assert r["level"] == "ip" and r["risk"] == ""


def test_public_suffix_multilevel():
    from app.domain_level import public_suffix, registrable_domain
    assert public_suffix("a.b.example.com.cn") == "com.cn"
    assert registrable_domain("a.b.example.com.cn") == "example.com.cn"
    assert registrable_domain("a.example.com") == "example.com"
    assert registrable_domain("example.com") == "example.com"
    assert registrable_domain("com") == ""          # 域名即后缀


# ---------------- API 入口拒绝 ----------------

@pytest.fixture()
def client():
    from app.main import app
    from app.db import db_cursor
    with db_cursor() as cur:
        cur.execute("DELETE FROM filter_list")
    with TestClient(app) as c:
        r = c.post("/api/auth/login", json={
            "username": "admin", "password": "admin123"})
        c.headers["Authorization"] = "Bearer " + r.json()["data"]["token"]
        yield c
    from app.db import db_cursor as _dbc
    with _dbc() as cur:
        cur.execute("DELETE FROM filter_list")


def test_create_rejects_top_level_wildcard(client):
    """创建 *.com / *.com.cn → 400 拒绝（白黑名单都拒绝）。"""
    for lt in ("whitelist", "blacklist"):
        r = client.post("/api/list", json={
            "list_type": lt, "target": "domain", "value": "*.com"})
        assert r.status_code == 400
        assert "顶层通配" in r.json()["detail"]
        r = client.post("/api/list", json={
            "list_type": lt, "target": "domain", "value": "*.com.cn"})
        assert r.status_code == 400


def test_create_allows_domain_wildcard(client):
    """*.example.com 主域通配允许入库（警示不阻断）。"""
    r = client.post("/api/list", json={
        "list_type": "whitelist", "target": "domain",
        "value": "*.example.com"})
    assert r.status_code == 200
    item_id = r.json()["data"]["id"]
    r = client.delete(f"/api/list/{item_id}")
    assert r.status_code == 200


def test_update_rejects_top_level_wildcard(client):
    """更新已有条目为 *.com 同样拒绝（防绕过：先建合法再改恶）。"""
    r = client.post("/api/list", json={
        "list_type": "blacklist", "target": "domain",
        "value": "safe.example.com"})
    item_id = r.json()["data"]["id"]
    r = client.put(f"/api/list/{item_id}", json={"value": "*.net"})
    assert r.status_code == 400
    assert "顶层通配" in r.json()["detail"]
    client.delete(f"/api/list/{item_id}")


def test_import_skips_top_level_wildcard(client):
    """CSV 导入：顶层通行行跳过并汇总原因，合法行正常入库。"""
    csv_text = (
        "blacklist,domain,good1.example.com,1,正常\n"
        "blacklist,domain,*.com,1,顶层通配\n"
        "blacklist,domain,*.co.uk,1,顶层通配多级\n"
        "blacklist,domain,good2.example.org,1,正常\n"
        "blacklist,domain,*.bad-site.example,1,主域通配合法\n"
    )
    r = client.post("/api/list/import", content=csv_text.encode(),
                    headers={"Content-Type": "text/csv; charset=utf-8"})
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["imported"] == 3
    assert d["skipped"] == 2
    assert any("*.com" in e for e in d["errors"])
    assert any("*.co.uk" in e for e in d["errors"])


# ---------------- 层级筛选与展示 ----------------

def test_list_level_filter_and_risk_flags(client):
    """列表接口：层级/通配筛选 + 每条目附 level/wildcard/risk。"""
    rows = [
        ("whitelist", "domain", "w-tld.example.com"),      # 子域
        ("whitelist", "domain", "example.com"),            # 主域
        ("whitelist", "domain", "*.example.net"),          # 主域通配 warn
        ("whitelist", "domain", "a.b.example.org"),        # 子域
        ("whitelist", "ip", "10.0.0.0/8"),
    ]
    for lt, tg, v in rows:
        client.post("/api/list", json={
            "list_type": lt, "target": tg, "value": v})

    # 全量：每条都带分级字段
    r = client.get("/api/list?list_type=whitelist&size=50")
    d = r.json()["data"]
    assert d["total"] == 5
    for it in d["items"]:
        assert "level" in it and "wildcard" in it and "risk" in it

    # 层级筛选：主域
    r = client.get("/api/list?list_type=whitelist&domain_level=registrable")
    items = r.json()["data"]["items"]
    assert {i["value"] for i in items} == {"example.com", "*.example.net"}
    # 主域通配带 warn 标记
    wc = next(i for i in items if i["value"] == "*.example.net")
    assert wc["risk"] == "warn" and wc["wildcard"] is True

    # 层级筛选：子域
    r = client.get("/api/list?list_type=whitelist&domain_level=subdomain")
    assert {i["value"] for i in r.json()["data"]["items"]} == {
        "w-tld.example.com", "a.b.example.org"}

    # 通配筛选
    r = client.get("/api/list?list_type=whitelist&wildcard=true")
    assert {i["value"] for i in r.json()["data"]["items"]} == {
        "*.example.net"}
    r = client.get("/api/list?list_type=whitelist&wildcard=false")
    assert "*.example.net" not in {
        i["value"] for i in r.json()["data"]["items"]}

    # 层级筛选不影响 IP 条目（target=domain 才参与层级口径）
    r = client.get("/api/list?list_type=whitelist&target=ip")
    assert r.json()["data"]["total"] == 1

    # 非法层级参数 → 400
    r = client.get("/api/list?domain_level=bogus")
    assert r.status_code == 400


def test_list_legacy_tld_wildcard_flagged(client):
    """存量脏数据（防护上线前已入库的 *.com）：列表不炸、
    risk=blocked 标红提示删除（入口拦截不影响存量展示）。"""
    from app.db import db_cursor
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO filter_list
               (list_type, target, value, enabled, remark, created_by)
               VALUES ('blacklist', 'domain', '*.com', 1, '历史脏数据', 'admin')""")
    r = client.get("/api/list?list_type=blacklist")
    items = r.json()["data"]["items"]
    assert any(i["value"] == "*.com" and i["risk"] == "blocked"
               and i["level"] == "tld" for i in items)
    # 存量按 tld 层级可筛出（排查入口）
    r = client.get("/api/list?list_type=blacklist&domain_level=tld")
    assert any(i["value"] == "*.com"
               for i in r.json()["data"]["items"])
