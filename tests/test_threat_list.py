"""离线大名单（hagezi / StevenBlack）测试。

覆盖：
- 解析：plain / hosts / adblock 格式、URL/端口/通配符规范化、注释与本地项跳过、去重
- 导入与匹配：整源替换、父域后缀匹配、IP 精确匹配、缓存失效
- Web API：sources / import / query / enable / delete
- 检测主流程：大名单命中即拦截（filter_reason=threat_list）
"""

import sys
import os

import pytest
from dnslib import DNSRecord, QTYPE, A
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "platform"))

from app.main import app  # noqa: E402
from app import threat_list  # noqa: E402
from app.db import db_cursor  # noqa: E402
from config import CONFIG  # noqa: E402


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def token(client):
    r = client.post("/api/auth/login", json={
        "username": "admin", "password": CONFIG.admin_initial_password,
    })
    assert r.status_code == 200
    return r.json()["data"]["token"]


def _h(token):
    return {"Authorization": f"Bearer {token}"}


def _wait_import(client, token, source, timeout=5.0):
    """轮询导入任务到终态（done/error），返回最终状态数据。"""
    import time
    deadline = time.time() + timeout
    d = None
    while time.time() < deadline:
        d = client.get(f"/api/threatlist/import/status?source={source}",
                       headers=_h(token)).json()["data"]
        if d["status"] in ("done", "error"):
            return d
        time.sleep(0.02)
    raise AssertionError(f"导入任务 {source} 未在 {timeout}s 内收敛: {d}")


# ---------------- 解析 ----------------

def test_parse_plain():
    text = "\n".join([
        "# comment", "",
        "bad1.example.com",
        "bad2.example.com",
        "   bad3.example.com  ",
        "bad1.example.com",          # 重复
    ])
    vals = threat_list.parse_content(text, "plain")
    assert vals == ["bad1.example.com", "bad2.example.com", "bad3.example.com"]


def test_parse_hosts():
    text = "\n".join([
        "# StevenBlack hosts",
        "0.0.0.0 ads.example.com",
        "127.0.0.1 tracker.example.net",
        "0.0.0.0 localhost",             # 本地保留项跳过
        "127.0.0.1 localhost.localdomain",
        "::1 localhost",
        "0.0.0.0 broadcasthost",
        "# 0.0.0.0 commented.example.com",
        "255.255.255.255 broadcasthost",
    ])
    vals = threat_list.parse_content(text, "hosts")
    assert vals == ["ads.example.com", "tracker.example.net"]


def test_parse_adblock_and_urls():
    text = "\n".join([
        "||evil.example.com^",
        "https://phishing.example.net/path?x=1",
        "http://malware.example.org:8080/",
        "hxxp://obfuscated.example.io^",
    ])
    vals = threat_list.parse_content(text, "plain")
    assert vals == ["evil.example.com", "phishing.example.net",
                    "malware.example.org", "obfuscated.example.io"]


def test_parse_auto_detects_hosts():
    text = "0.0.0.0 ads.example.com\n0.0.0.0 track.example.com"
    assert threat_list.parse_content(text, "auto") == [
        "ads.example.com", "track.example.com"]


def test_parse_invalid_skipped():
    text = "\n".join(["", "not a domain!!", "1.2.3.4", "https://",
                      "a" * 300])
    assert threat_list.parse_content(text, "plain") == []


def test_parse_wildcard_to_base():
    """adblock 通配符条目（*.x.com）按主域处理，避免解析为非法名被丢弃。"""
    assert threat_list.parse_content("*.example.com\n", "plain") == [
        "example.com"]


# ---------------- 导入与匹配 ----------------

def test_import_and_match():
    threat_list.import_source("hagezi_ti", "bad.com\nsub.bad.org\n")
    try:
        # 精确命中
        assert threat_list.check_domain("bad.com")
        # 父域后缀命中：a.bad.com → bad.com
        assert threat_list.check_domain("a.bad.com")
        assert threat_list.check_domain("deep.a.bad.com")
        # 未命中
        assert not threat_list.check_domain("good.com")
        assert not threat_list.check_domain("notbad.com")  # 不能误伤后缀相似
        # 命中来源信息
        assert threat_list.find_domain("x.sub.bad.org") == ("hagezi_ti",
                                                            "sub.bad.org")
    finally:
        threat_list.delete_source("hagezi_ti")


def test_import_replaces_source():
    threat_list.import_source("stevenblack", "one.com\ntwo.com\n")
    threat_list.import_source("stevenblack", "three.com\n")
    try:
        assert threat_list.check_domain("one.com") is False  # 已整源替换
        assert threat_list.check_domain("three.com")
    finally:
        threat_list.delete_source("stevenblack")


def test_enable_toggle_and_cache():
    threat_list.import_source("hagezi_ti", "off.example.com\n")
    try:
        assert threat_list.check_domain("off.example.com")
        threat_list.enable_source("hagezi_ti", False)
        assert not threat_list.check_domain("off.example.com")  # 缓存已失效重载
        threat_list.enable_source("hagezi_ti", True)
        assert threat_list.check_domain("off.example.com")
    finally:
        threat_list.delete_source("hagezi_ti")


def test_source_stats():
    threat_list.import_source("hagezi_ti", "s1.com\ns2.com\n")
    try:
        stats = threat_list.source_stats()
        assert stats["hagezi_ti"]["total"] == 2
        assert stats["hagezi_ti"]["enabled_cnt"] == 2
        assert stats["hagezi_ti"]["updated_at"]
        # 内置 5 个来源元数据始终存在
        assert set(stats) >= {"hagezi_ti", "hagezi_ult", "stevenblack",
                              "urlhaus", "oisd"}
    finally:
        threat_list.delete_source("hagezi_ti")


# ---------------- 下载与镜像降级 ----------------

def test_mirror_of_rules():
    assert threat_list._mirror_of(
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt"
    ) == "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt"
    # oisd 仓库同样有 jsDelivr 镜像
    assert threat_list._mirror_of(
        "https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild_big.txt"
    ) == "https://cdn.jsdelivr.net/gh/sjhgvr/oisd@main/domainswild_big.txt"
    # 非已知仓库地址无镜像
    assert threat_list._mirror_of(
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts") is None
    assert threat_list._mirror_of(
        "https://urlhaus.abuse.ch/downloads/hostfile/") is None


def test_download_uses_main_then_mirror(monkeypatch):
    calls = []
    def fake_once(url, max_bytes, timeout_s, progress=None):
        calls.append(url)
        if calls.count(url) == 1 and "raw.githubusercontent" in url:
            raise ConnectionError("timeout")
        return "a.com\nb.com\n"
    monkeypatch.setattr(threat_list, "_download_once", fake_once)
    text = threat_list.download(
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt",
        timeout_s=30)
    assert text == "a.com\nb.com\n"
    assert len(calls) == 2
    assert "cdn.jsdelivr.net" in calls[1]   # 已降级镜像


def test_download_success_no_mirror(monkeypatch):
    calls = []
    def fake_once(url, max_bytes, timeout_s, progress=None):
        calls.append(url)
        return "x.com\n"
    monkeypatch.setattr(threat_list, "_download_once", fake_once)
    threat_list.download("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")
    assert len(calls) == 1   # 主地址成功不触发镜像


def test_download_mirror_also_fails_raises(monkeypatch):
    def fake_once(url, max_bytes, timeout_s, progress=None):
        raise ConnectionError("both down")
    monkeypatch.setattr(threat_list, "_download_once", fake_once)
    with pytest.raises(ConnectionError):
        threat_list.download(
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt")


# ---------------- 条目分页查看 ----------------

def test_list_entries_paging_and_filter():
    threat_list.import_source("hagezi_ti", "aaa.com\nbbb.com\nccc.com\n")
    threat_list.enable_source("hagezi_ti", False)
    try:
        # 全量分页（page=1, size=2）
        d = threat_list.list_entries("hagezi_ti", page=1, size=2)
        assert d["total"] == 3
        assert [i["value"] for i in d["items"]] == ["aaa.com", "bbb.com"]
        # 第二页
        d2 = threat_list.list_entries("hagezi_ti", page=2, size=2)
        assert [i["value"] for i in d2["items"]] == ["ccc.com"]
        # 关键字子串过滤
        d3 = threat_list.list_entries("hagezi_ti", keyword="BB")
        assert d3["total"] == 1 and d3["items"][0]["value"] == "bbb.com"
        # 状态过滤（全部已停用）
        d4 = threat_list.list_entries("hagezi_ti", enabled=False)
        assert d4["total"] == 3
        d5 = threat_list.list_entries("hagezi_ti", enabled=True)
        assert d5["total"] == 0
        # 不存在的来源
        assert threat_list.list_entries("no_such")["total"] == 0
    finally:
        threat_list.delete_source("hagezi_ti")


def test_list_entries_size_cap():
    threat_list.import_source("hagezi_ti", "a.com\nb.com\nc.com\n")
    try:
        d = threat_list.list_entries("hagezi_ti", page=1, size=9999)
        assert len(d["items"]) == 3   # 上限 500 不会爆内存
        assert threat_list.list_entries("hagezi_ti", page=0, size=0)["total"] == 3
    finally:
        threat_list.delete_source("hagezi_ti")


# ---------------- Web API ----------------

def test_sources_api(client, token):
    r = client.get("/api/threatlist/sources", headers=_h(token))
    assert r.status_code == 200
    keys = {i["key"] for i in r.json()["data"]["items"]}
    assert keys == {"hagezi_ti", "hagezi_ult", "stevenblack",
                    "urlhaus", "oisd"}
    # 新源带更新周期元数据
    by_key = {i["key"]: i for i in r.json()["data"]["items"]}
    assert by_key["urlhaus"]["update_interval_s"] == 30 * 60
    assert by_key["oisd"]["update_interval_s"] == 24 * 3600


def test_domains_api(client, token):
    threat_list.import_source("hagezi_ti",
                              "evil-a.example\nphish-b.example\nok-c.example\n")
    try:
        # 分页 + 关键字 + 状态组合
        r = client.get("/api/threatlist/domains?source=hagezi_ti&page=1&size=2",
                       headers=_h(token))
        assert r.status_code == 200
        d = r.json()["data"]
        assert d["total"] == 3 and len(d["items"]) == 2
        assert d["items"][0]["value"] == "evil-a.example"

        r = client.get("/api/threatlist/domains?source=hagezi_ti&keyword=phish",
                       headers=_h(token))
        d = r.json()["data"]
        assert d["total"] == 1 and d["items"][0]["value"] == "phish-b.example"

        # 停用后按状态过滤
        threat_list.enable_source("hagezi_ti", False)
        r = client.get("/api/threatlist/domains?source=hagezi_ti&enabled=1",
                       headers=_h(token))
        assert r.json()["data"]["total"] == 0
        r = client.get("/api/threatlist/domains?source=hagezi_ti&enabled=0",
                       headers=_h(token))
        assert r.json()["data"]["total"] == 3

        # 参数校验
        assert client.get("/api/threatlist/domains", headers=_h(token)).status_code == 422
        assert client.get("/api/threatlist/domains?source=hagezi_ti&size=9999",
                          headers=_h(token)).status_code == 422
        # 未认证
        assert client.get("/api/threatlist/domains?source=hagezi_ti").status_code == 401
    finally:
        threat_list.delete_source("hagezi_ti")


def test_import_query_enable_delete_api(client, token, monkeypatch):
    import app.threat_list as tl_mod
    monkeypatch.setattr(tl_mod, "download",
                        lambda url, timeout_s=90, progress=None:
                        "ads.bad.example\nphish.bad.example\n")
    # 导入（用内置 key，url 省略）→ 后台任务，轮询至完成
    r = client.post("/api/threatlist/import",
                    json={"source": "hagezi_ti", "enabled": True},
                    headers=_h(token))
    assert r.status_code == 200
    assert r.json()["data"]["task"] == "started"
    st = _wait_import(client, token, "hagezi_ti")
    assert st["status"] == "done" and st["total"] == 2

    # 查询命中（父域后缀）
    r = client.get("/api/threatlist/query?value=x.ads.bad.example",
                   headers=_h(token))
    d = r.json()["data"]
    assert d["threat_list"]["matched"] and d["threat_list"]["source"] == "hagezi_ti"

    # 查询未命中
    r = client.get("/api/threatlist/query?value=good.example",
                   headers=_h(token))
    assert not r.json()["data"]["threat_list"]["matched"]

    # 整体停用
    r = client.put("/api/threatlist/source",
                   json={"source": "hagezi_ti", "enabled": False},
                   headers=_h(token))
    assert r.status_code == 200
    r = client.get("/api/threatlist/query?value=ads.bad.example",
                   headers=_h(token))
    assert not r.json()["data"]["threat_list"]["matched"]

    # 清空
    r = client.delete("/api/threatlist/source?source=hagezi_ti",
                      headers=_h(token))
    assert r.json()["data"]["deleted"] == 2
    r = client.get("/api/threatlist/sources", headers=_h(token))
    item = next(i for i in r.json()["data"]["items"]
                if i["key"] == "hagezi_ti")
    assert item["total"] == 0


def test_import_custom_url(client, token, monkeypatch):
    import app.threat_list as tl_mod
    monkeypatch.setattr(tl_mod, "download",
                        lambda url, timeout_s=90, progress=None:
                        "custom.com\n")
    r = client.post("/api/threatlist/import",
                    json={"url": "https://example.com/my-list.txt"},
                    headers=_h(token))
    assert r.status_code == 200
    assert r.json()["data"]["source"] == "custom"
    st = _wait_import(client, token, "custom")
    assert st["status"] == "done" and st["total"] == 1
    r = client.get("/api/threatlist/query?value=custom.com",
                   headers=_h(token))
    assert r.json()["data"]["threat_list"]["source"] == "custom"
    client.delete("/api/threatlist/source?source=custom", headers=_h(token))


def test_import_empty_list_rejected(client, token, monkeypatch):
    import app.threat_list as tl_mod
    monkeypatch.setattr(tl_mod, "download",
                        lambda url, timeout_s=90, progress=None:
                        "# only comments\n\n")
    r = client.post("/api/threatlist/import",
                    json={"source": "hagezi_ti"}, headers=_h(token))
    assert r.status_code == 200
    st = _wait_import(client, token, "hagezi_ti")
    assert st["status"] == "error"       # 空列表 → 后台任务报错
    assert "无有效域名" in (st["error"] or "")


def test_import_unknown_source(client, token):
    r = client.post("/api/threatlist/import",
                    json={"source": "not_exist"}, headers=_h(token))
    assert r.status_code == 400


def test_threatlist_requires_auth(client):
    assert client.get("/api/threatlist/sources").status_code == 401
    assert client.get("/api/threatlist/query?value=x").status_code == 401


# ---------------- 检测主流程接入 ----------------

def test_process_query_intercepts_threat_list(monkeypatch):
    from detectors import process_query
    threat_list.import_source("hagezi_ti", "evil.bad.example\n")
    try:
        monkeypatch.setattr(CONFIG, "detection_enabled", True)
        req = DNSRecord.question("a.evil.bad.example", "A")
        reply = process_query(req, "192.168.1.10")
        # 大名单命中：NOERROR + alert_ip 应答（拦截），不发起公网解析
        assert reply.header.rcode == 0
        answers = [rr for rr in reply.rr if rr.rtype == QTYPE.A]
        assert answers and str(answers[0].rdata) == CONFIG.alert_ip
        with db_cursor() as cur:
            cur.execute(
                "SELECT filter_reason FROM filter_log "
                "WHERE domain='a.evil.bad.example' ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
        assert row and row["filter_reason"] == "threat_list"
    finally:
        threat_list.delete_source("hagezi_ti")


def test_process_query_whitelist_beats_threat_list(monkeypatch):
    """白名单优先级高于大名单：同时命中时放行。"""
    from detectors import process_query
    threat_list.import_source("hagezi_ti", "wl.bad.example\n")
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO filter_list (list_type, target, value, enabled) "
            "VALUES ('whitelist','domain','wl.bad.example',1)")
    try:
        monkeypatch.setattr(CONFIG, "detection_enabled", True)
        monkeypatch.setattr(CONFIG, "allow_log_enabled", False)
        monkeypatch.setattr(CONFIG, "upstream_dns", "127.0.0.1:1")  # 快速失败
        req = DNSRecord.question("wl.bad.example", "A")
        # 白名单放行会走公网解析（无上游 → SERVFAIL），绝不会返回拦截应答
        reply = process_query(req, "192.168.1.10")
        answers = [rr for rr in reply.rr if rr.rtype == QTYPE.A]
        assert not answers  # 无 alert_ip 即未拦截
    finally:
        threat_list.delete_source("hagezi_ti")
        with db_cursor() as cur:
            cur.execute("DELETE FROM filter_list WHERE value='wl.bad.example'")


# ---------------- 导入进度（后台任务 + 状态轮询） ----------------

def test_begin_import_running_guard():
    """同一来源并发导入被拒绝；结束后可再次发起。"""
    t = threat_list.begin_import("hagezi_ti")
    assert t is not None and t["status"] == "running"
    assert t["started_at"]
    try:
        assert threat_list.begin_import("hagezi_ti") is None  # 并发拒绝
    finally:
        t.update(status="idle", stage="", message="", error=None,
                 finished_at=None)
    assert threat_list.begin_import("hagezi_ti") is not None
    threat_list.import_progress("hagezi_ti").update(status="idle")


def test_parse_import_progress_fields():
    """函数级：解析与导入过程更新进度字段。"""
    prog = {"parsed": 0}
    vals = threat_list.parse_content("a.com\nb.com\nc.com\n", progress=prog)
    assert prog["parsed"] == 3
    assert vals == ["a.com", "b.com", "c.com"]

    prog2 = {"stage": "insert", "total": 0, "inserted": 0, "message": ""}
    try:
        threat_list.import_source("hagezi_ti", "x.com\ny.com\n",
                                  progress=prog2)
        assert prog2["stage"] == "insert"
        assert prog2["total"] == 2
        assert prog2["inserted"] == 2
    finally:
        threat_list.delete_source("hagezi_ti")


def test_import_api_async_progress(client, token, monkeypatch):
    """POST /import 立即返回 started；轮询 status 至 done 且数据入库。"""
    import time
    monkeypatch.setattr(threat_list, "download",
                        lambda *a, **k: "p1.com\np2.com\np3.com\n")
    r = client.post("/api/threatlist/import",
                    json={"source": "hagezi_ti", "enabled": True},
                    headers=_h(token))
    assert r.status_code == 200
    assert r.json()["data"] == {"task": "started", "source": "hagezi_ti"}

    data = None
    for _ in range(200):
        data = client.get("/api/threatlist/import/status?source=hagezi_ti",
                          headers=_h(token)).json()["data"]
        if data["status"] in ("done", "error"):
            break
        time.sleep(0.02)
    assert data["status"] == "done", data
    assert data["total"] == 3
    assert data["inserted"] == 3
    assert data["finished_at"]

    # 数据已真实入库
    items = client.get("/api/threatlist/sources",
                       headers=_h(token)).json()["data"]["items"]
    s = next(i for i in items if i["key"] == "hagezi_ti")
    assert s["total"] == 3
    threat_list.delete_source("hagezi_ti")


def test_import_conflict_409(client, token):
    """来源导入进行中时再次提交 → 409。"""
    t = threat_list.begin_import("hagezi_ti")
    try:
        r = client.post("/api/threatlist/import",
                        json={"source": "hagezi_ti", "enabled": True},
                        headers=_h(token))
        assert r.status_code == 409
    finally:
        t.update(status="idle", stage="", message="", error=None,
                 finished_at=None)


# ---------------- 按源周期自动更新（urlhaus 短周期 / 大名单每日） ----------------

def test_source_due_logic():
    """source_due：未导入→到期；刚导入→未到期；时间过期→到期。"""
    # 从未导入（先确保干净）
    threat_list.delete_source("hagezi_ult")
    assert threat_list.source_due("hagezi_ult", 24 * 3600) is True

    threat_list.import_source("hagezi_ult", "due.com\n")
    try:
        # 刚导入：24h 周期未到期，30 分钟周期也未到期
        assert threat_list.source_due("hagezi_ult", 24 * 3600) is False
        assert threat_list.source_due("hagezi_ult", 30 * 60) is False

        # 人为把最近更新时间改旧 → 到期
        with db_cursor() as cur:
            cur.execute(
                "UPDATE threat_list SET updated_at=? WHERE source=?",
                ("2020-01-01 00:00:00", "hagezi_ult"))
        assert threat_list.source_due("hagezi_ult", 24 * 3600) is True
        assert threat_list.source_due("hagezi_ult", 1) is True
    finally:
        threat_list.delete_source("hagezi_ult")


def test_auto_update_once_respects_interval(monkeypatch):
    """自动更新轮：到期源被下载替换，未到期源标记 skipped 不下载。"""
    import app.threat_list as tl_mod
    # 两个启用源：hagezi_ti 刚导入（未到期），urlhaus 时间被改旧（到期）
    threat_list.delete_source("hagezi_ti")
    threat_list.delete_source("urlhaus")
    threat_list.import_source("hagezi_ti", "keep.com\n")
    threat_list.import_source("urlhaus", "old.com\n")
    with db_cursor() as cur:
        cur.execute("UPDATE threat_list SET updated_at=? WHERE source=?",
                    ("2020-01-01 00:00:00", "urlhaus"))

    calls = []
    monkeypatch.setattr(tl_mod, "download",
                        lambda *a, **k: calls.append(a[0]) or "new.com\n")
    try:
        results = threat_list.auto_update_once()
        # 未到期源：skipped，未触发下载
        assert results["hagezi_ti"]["ok"] is True
        assert results["hagezi_ti"]["skipped"] is True
        # 到期源：下载并整源替换
        assert results["urlhaus"]["ok"] is True
        assert results["urlhaus"]["skipped"] is False
        assert results["urlhaus"]["imported"] == 1
        assert len(calls) == 1
        assert "urlhaus.abuse.ch" in calls[0]
        # 数据已替换
        assert not threat_list.check_domain("old.com")
        assert threat_list.check_domain("new.com")
    finally:
        threat_list.delete_source("hagezi_ti")
        threat_list.delete_source("urlhaus")


def test_auto_update_tick_min_src(monkeypatch):
    """调度 tick = min(配置间隔, 内置源最小更新周期)，能覆盖 30 分钟短周期。"""
    from app import auto_update
    monkeypatch.setattr(auto_update.CONFIG, "threatlist_auto_interval_hours", 24)
    t = auto_update.tick_seconds()
    assert t <= 30 * 60            # 至少能覆盖 urlhaus 30 分钟周期
    assert t >= auto_update._TICK_MIN_S
    # 用户配置更短时也受源周期限制（不短于下限）
    monkeypatch.setattr(auto_update.CONFIG, "threatlist_auto_interval_hours", 1)
    assert auto_update.tick_seconds() <= 30 * 60
    # 用户配置非法 → 仍能得出合理 tick
    monkeypatch.setattr(auto_update.CONFIG, "threatlist_auto_interval_hours", "xx")
    assert auto_update.tick_seconds() <= 30 * 60
