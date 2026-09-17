"""银狐情报共享站离线源（迭代 43，API 拉取型）测试。

覆盖：
- classify：IPv4/IPv6/域名/哈希丢弃/带端口路径丢弃
- _url_hosts：URL 提取 host（域名 + IP 双收集——09-17 归因 91 个
  投毒下载源 IP 仅存于 URL）
- _extra_entries：本地追加文件（silverfox_extra.txt）分流/容错/缺失
- fetch_iocs：事件聚合 / hot-ioc 合并 / 追加文件合并 / 空结果保护 /
  连续失败熔断 / window_days 窗口（全 mock，不打真实接口）
- import_api_source：域名+IP 双 target 整源替换 / 空结果拒绝 / PTR 反查命中
- auto_update_once：API 源分支走 fetch_iocs 而非 download
- 路由：POST /api/threatlist/import {source: silverfox} 后台任务完整跑通
- 配置：silverfox_window_days 热生效 + 范围校验
"""

import sys
import os
import time

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "platform"))

from app.main import app  # noqa: E402
from app import silverfox  # noqa: E402
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


@pytest.fixture(autouse=True)
def no_rate_limit(monkeypatch):
    """限速归零（time.sleep(0) 即时返回；不能 patch time.sleep 本体——
    轮询后台任务进度的 sleep 依赖真实等待，否则会空转断言抖动）；
    追加文件指向不存在的文件名（本地 data/silverfox_extra.txt 若存在
    会混入 fetch 断言；test_extra_entries 用显式路径不受影响）。"""
    monkeypatch.setattr(silverfox, "_REQUEST_INTERVAL", 0)
    monkeypatch.setattr(silverfox, "_EXTRA_FILENAME", "_no_such_extra.txt")


# ---------------- classify / _url_hosts ----------------

def test_classify_basic():
    assert silverfox.classify("18.166.168.216") == ("ip", "18.166.168.216")
    assert silverfox.classify("2001:db8::1") == ("ip", "2001:db8::1")
    assert silverfox.classify("baidu787.com") == ("domain", "baidu787.com")
    assert silverfox.classify("6001.baidu787.com") == ("domain", "6001.baidu787.com")
    assert silverfox.classify("WWW.Ryzhe.COM") == ("domain", "www.ryzhe.com")


def test_classify_rejects():
    assert silverfox.classify("") is None
    # 哈希（MD5/SHA1/SHA256）丢弃
    assert silverfox.classify("d41d8cd98f00b204e9800998ecf8427e") is None
    assert silverfox.classify("a" * 40) is None
    assert silverfox.classify("b" * 64) is None
    # 带端口/路径/通配/掩码
    assert silverfox.classify("1.2.3.4:8080") is None
    assert silverfox.classify("http://evil.com/a") is None
    assert silverfox.classify("*.evil.com") is None
    assert silverfox.classify("1.2.3.0/24") is None
    # 纯标签非域名（无点）
    assert silverfox.classify("localhost") is None
    assert silverfox.classify("银狐投毒") is None


def test_url_hosts():
    urls = [
        "https://noah-relay.wotudj578.workers.dev/x",
        "http://evil.com.cn:8080/payload.exe",
        "http://103.156.25.35/payload.exe",   # IP host（归因：91 个仅存于 URL）
        "not-a-url",
        "",
    ]
    hosts, ips = silverfox._url_hosts(urls)
    assert hosts == {"noah-relay.wotudj578.workers.dev", "evil.com.cn"}
    assert ips == {"103.156.25.35"}


def test_extra_entries(tmp_path):
    # 文件不存在 → 空集
    assert silverfox._extra_entries(str(tmp_path / "none.txt")) == (set(), set())
    p = tmp_path / "silverfox_extra.txt"
    p.write_text(
        "vuxu661d.com\n"             # 注册域裸条目（父域匹配等效 *. 通配）
        "103.156.25.35\n"            # IP 分流
        "# 注释行 classify 不认自动丢弃\n"
        "\n"
        "http://not-plain.com/a\n"   # 非裸条目丢弃
        "*.wildcard.com\n",          # 通配丢弃（threat_list 不支持通配）
        encoding="utf-8")
    d, i = silverfox._extra_entries(str(p))
    assert d == {"vuxu661d.com"}
    assert i == {"103.156.25.35"}


# ---------------- fetch_iocs（mock 接口） ----------------

def _event(uuid, domains=(), ips=(), iocs=(), urls=()):
    return {"data": {"related_ioc_list_v2": {
        "domain": list(domains), "ip": list(ips),
        "ioc": list(iocs), "url": list(urls)}}}


def test_fetch_iocs_aggregates(monkeypatch):
    calls = []

    def fake_get(path, params=None, retries=3):
        calls.append((path, dict(params or {})))
        if path.endswith("get-humans"):
            # 窗口足够小（window_days=30 → 单窗），返回两个事件
            return {"data": {"data": [{"uuid": "u1"}, {"uuid": "u2"}]}}
        if path.endswith("get-human"):
            uid = params["uuid"]
            if uid == "u1":
                return _event("u1",
                              domains=["baidu787.com"],
                              ips=["18.166.168.216"],
                              iocs=["www.ryzhe.com", "deadbeef" * 8],  # 混入 SHA256
                              urls=["https://noah-ssh.top/a.exe",
                                    "http://8.210.165.181/x.exe"])    # IP host URL
            return _event("u2", ips=["2001:db8::9"])
        if path.endswith("get-hot-ioc"):
            return {"data": {"domain": ["hot-evil.xyz"], "ip": ["1.2.3.4"],
                             "label": "C2"}}
        raise AssertionError(f"unexpected path {path}")

    monkeypatch.setattr(silverfox, "_get_json", fake_get)
    prog = {}
    res = silverfox.fetch_iocs(progress=prog, window_days=30)
    # 事件 IOC + URL 提取（域名与 IP host）+ hot-ioc 合并；哈希被丢弃
    assert set(res["domains"]) == {"baidu787.com", "www.ryzhe.com",
                                   "noah-ssh.top", "hot-evil.xyz"}
    assert set(res["ips"]) == {"18.166.168.216", "2001:db8::9", "1.2.3.4",
                               "8.210.165.181"}
    assert res["events"] == 2
    assert res["failed_events"] == 0
    # 进度字段被更新（download 阶段复用 parsed/total）
    assert prog["stage"] == "download"
    assert prog["total"] == 2 and prog["parsed"] == 2


def test_fetch_iocs_merges_extra(monkeypatch):
    """本地追加条目（silverfox_extra.txt）随每轮 fetch 合入结果。"""
    def fake_get(path, params=None, retries=3):
        if path.endswith("get-humans"):
            return {"data": {"data": [{"uuid": "u1"}]}}
        if path.endswith("get-human"):
            return _event("u1", domains=["a.evil.com"])
        return {"data": {}}

    monkeypatch.setattr(silverfox, "_get_json", fake_get)
    monkeypatch.setattr(silverfox, "_extra_entries",
                        lambda path=None: ({"vuxu661d.com"}, {"8.8.4.4"}))
    res = silverfox.fetch_iocs(window_days=30)
    assert set(res["domains"]) == {"a.evil.com", "vuxu661d.com"}
    assert set(res["ips"]) == {"8.8.4.4"}


def test_fetch_iocs_empty_guard(monkeypatch):
    monkeypatch.setattr(silverfox, "_get_json",
                        lambda path, params=None, retries=3: {"data": {}})
    # 事件列表为空 → 拒绝
    with pytest.raises(RuntimeError, match="事件列表为空"):
        silverfox.fetch_iocs(window_days=30)


def test_fetch_iocs_consecutive_fail_abort(monkeypatch):
    def fake_get(path, params=None, retries=3):
        if path.endswith("get-humans"):
            return {"data": {"data": [{"uuid": f"u{i}"} for i in
                                      range(silverfox._MAX_CONSECUTIVE_FAILS + 5)]}}
        raise RuntimeError("blocked")

    monkeypatch.setattr(silverfox, "_get_json", fake_get)
    with pytest.raises(RuntimeError, match="连续"):
        silverfox.fetch_iocs(window_days=30)


def test_fetch_iocs_single_fail_tolerated(monkeypatch):
    """单事件失败不中断（< 熔断阈值），其余事件照常收割。"""
    def fake_get(path, params=None, retries=3):
        if path.endswith("get-humans"):
            return {"data": {"data": [{"uuid": "u1"}, {"uuid": "u2"}]}}
        if path.endswith("get-human"):
            if params["uuid"] == "u1":
                raise RuntimeError("transient")
            return _event("u2", domains=["ok.example"])
        return {"data": {}}

    monkeypatch.setattr(silverfox, "_get_json", fake_get)
    res = silverfox.fetch_iocs(window_days=30)
    assert res["domains"] == ["ok.example"]
    assert res["failed_events"] == 1


def test_fetch_iocs_window_days_from_config(monkeypatch):
    """window_days=None 时读 CONFIG.silverfox_window_days。"""
    seen_windows = []

    def fake_get(path, params=None, retries=3):
        if path.endswith("get-humans"):
            seen_windows.append(params["startTime"])
            return {"data": {"data": [{"uuid": "u1"}]}}
        if path.endswith("get-human"):
            return _event("u1", domains=["a.evil.com"])
        return {"data": {}}

    monkeypatch.setattr(silverfox, "_get_json", fake_get)
    monkeypatch.setattr(CONFIG, "silverfox_window_days", 30)
    silverfox.fetch_iocs()
    assert len(seen_windows) == 1        # 30 天 < 92 天步长 → 单窗
    # 0 = 全量回溯至 2023-06 → 多窗（2023-06 至今 > 3 年）
    monkeypatch.setattr(CONFIG, "silverfox_window_days", 0)
    silverfox.fetch_iocs()
    assert len(seen_windows) > 10


# ---------------- import_api_source ----------------

def test_import_api_source_dual_target():
    try:
        n = threat_list.import_api_source(
            "silverfox", ["baidu787.com", "noah-ssh.top"],
            ["18.166.168.216"])
        assert n == 3
        assert threat_list.check_domain("baidu787.com")
        assert threat_list.check_domain("6001.baidu787.com")  # 父域后缀匹配
        assert threat_list.check_ip("18.166.168.216")         # PTR 反查链
        # 整源替换：二次导入旧条目淘汰
        threat_list.import_api_source("silverfox", ["new.evil.com"], [])
        assert not threat_list.check_domain("baidu787.com")
        assert threat_list.check_domain("new.evil.com")
    finally:
        threat_list.delete_source("silverfox")


def test_import_api_source_empty_rejected():
    with pytest.raises(ValueError, match="拒绝整源替换"):
        threat_list.import_api_source("silverfox", [], [])
    # 空结果不落库
    with db_cursor() as cur:
        cur.execute("SELECT COUNT(*) AS c FROM threat_list WHERE source='silverfox'")
        assert cur.fetchone()["c"] == 0


def test_import_api_source_case_normalized():
    try:
        threat_list.import_api_source("silverfox", ["EVIL.com", "evil.com"],
                                      ["1.1.1.1"])
        with db_cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM threat_list "
                        "WHERE source='silverfox' AND value='evil.com'")
            assert cur.fetchone()["c"] == 1      # 大小写归一并消重
    finally:
        threat_list.delete_source("silverfox")


# ---------------- auto_update_once API 源分支 ----------------

def test_auto_update_once_silverfox_branch(monkeypatch):
    threat_list.import_api_source("silverfox", ["old.evil.com"], [])
    with db_cursor() as cur:
        cur.execute("UPDATE threat_list SET updated_at=? WHERE source='silverfox'",
                    ("2020-01-01 00:00:00",))
    download_called = []
    monkeypatch.setattr(threat_list, "download",
                        lambda *a, **k: download_called.append(a) or "x.com\n")

    def fake_fetch(progress=None, window_days=None):
        return {"domains": ["new.evil.com"], "ips": ["9.9.9.9"],
                "events": 1, "failed_events": 0}

    monkeypatch.setattr(silverfox, "fetch_iocs", fake_fetch)
    try:
        res = threat_list.auto_update_once()
        assert res["silverfox"]["ok"] is True
        assert res["silverfox"]["imported"] == 2
        assert not download_called            # API 源不走 download()
        assert threat_list.check_domain("new.evil.com")
        assert not threat_list.check_domain("old.evil.com")
        assert threat_list.check_ip("9.9.9.9")
    finally:
        threat_list.delete_source("silverfox")


def test_auto_update_api_source_not_shortened(monkeypatch):
    """API 拉取型源不受全局间隔缩短：1 小时前导入、全局间隔 1h →
    文件源到期、silverfox 未到 24h 周期跳过（防每小时全量重拉共享站）。"""
    fetch_called = []
    monkeypatch.setattr(silverfox, "fetch_iocs",
                        lambda progress=None, window_days=None:
                        fetch_called.append(1) or
                        {"domains": ["x.evil.com"], "ips": [],
                         "events": 1, "failed_events": 0})
    # hagezi_ti 到期会走文件下载路径——mock 掉防真实网络请求
    monkeypatch.setattr(threat_list, "download", lambda *a, **k: "dl.evil.com\n")
    threat_list.import_api_source("silverfox", ["sf.evil.com"], [])
    threat_list.import_source("hagezi_ti", "f.evil.com\n")
    with db_cursor() as cur:
        # 两源最近导入时间都设为 2 小时前（> 1h 全局间隔，< 24h 源周期）
        cur.execute("UPDATE threat_list SET updated_at=?",
                    ("2020-01-01 00:00:00",))
        cur.execute(
            "UPDATE threat_list SET updated_at=datetime('now','localtime','-2 hours') "
            "WHERE source IN ('silverfox','hagezi_ti')")
    try:
        res = threat_list.auto_update_once(user_interval_s=3600)
        # silverfox 未到 24h 自身周期 → 跳过且未拉取
        assert res["silverfox"]["skipped"] is True
        assert res["silverfox"]["imported"] == 0
        assert not fetch_called
        assert threat_list.check_domain("sf.evil.com")   # 旧数据保留
        # 调度口径一致：next_update_schedule 中 API 源保持源周期
        sched = threat_list.next_update_schedule(3600)
        assert sched["silverfox"]["effective_interval_s"] == 24 * 3600
        assert sched["hagezi_ti"]["effective_interval_s"] == 3600
    finally:
        threat_list.delete_source("silverfox")
        threat_list.delete_source("hagezi_ti")


# ---------------- 路由：后台导入任务完整跑通 ----------------

def test_router_import_silverfox_task(client, token, monkeypatch):
    def fake_fetch(progress=None, window_days=None):
        progress.update(total=1, parsed=1)
        return {"domains": ["router.evil.com"], "ips": ["8.8.4.4"],
                "events": 1, "failed_events": 0}

    monkeypatch.setattr(silverfox, "fetch_iocs", fake_fetch)
    try:
        r = client.post("/api/threatlist/import", json={"source": "silverfox",
                                                        "enabled": True},
                        headers=_h(token))
        assert r.status_code == 200
        # 后台线程轮询至 done（mock 数据秒级完成）
        for _ in range(50):
            t = threat_list.import_progress("silverfox")
            if t["status"] in ("done", "error"):
                break
            time.sleep(0.1)
        assert t["status"] == "done", t
        assert t["total"] == 2                     # 1 域名 + 1 IP
        assert threat_list.check_domain("router.evil.com")
        assert threat_list.check_ip("8.8.4.4")
        # 审计留痕（url 记 api:silverfox；done 状态先于审计写入，轮询等待）
        audited = False
        for _ in range(20):
            with db_cursor() as cur:
                cur.execute("SELECT detail FROM audit_log WHERE "
                            "action='threatlist_import' ORDER BY id DESC LIMIT 1")
                row = cur.fetchone()
            if row and "api:silverfox" in (row["detail"] or ""):
                audited = True
                break
            time.sleep(0.1)
        assert audited, "审计未记录 api:silverfox 导入"
    finally:
        threat_list.delete_source("silverfox")


def test_router_import_silverfox_failure_keeps_old(client, token, monkeypatch):
    """拉取失败时任务置 error，库中旧数据保留（fail-safe）。"""
    threat_list.import_api_source("silverfox", ["keep.evil.com"], [])

    def boom(progress=None, window_days=None):
        raise RuntimeError("接口被拦")

    monkeypatch.setattr(silverfox, "fetch_iocs", boom)
    try:
        r = client.post("/api/threatlist/import", json={"source": "silverfox",
                                                        "enabled": True},
                        headers=_h(token))
        assert r.status_code == 200
        for _ in range(50):
            t = threat_list.import_progress("silverfox")
            if t["status"] in ("done", "error"):
                break
            time.sleep(0.1)
        assert t["status"] == "error"
        assert "接口被拦" in t["error"]
        assert threat_list.check_domain("keep.evil.com")   # 旧数据未动
    finally:
        threat_list.delete_source("silverfox")


# ---------------- 配置键 ----------------

def test_config_silverfox_window(client, token):
    r = client.put("/api/config", json={"silverfox_window_days": 180},
                   headers=_h(token))
    assert r.status_code == 200
    assert CONFIG.silverfox_window_days == 180      # 热生效
    # 恢复默认 0（全量）
    client.put("/api/config", json={"silverfox_window_days": 0},
               headers=_h(token))
    assert CONFIG.silverfox_window_days == 0


def test_config_silverfox_window_range(client, token):
    r = client.put("/api/config", json={"silverfox_window_days": -1},
                   headers=_h(token))
    assert r.status_code == 400
    r = client.put("/api/config", json={"silverfox_window_days": 99999},
                   headers=_h(token))
    assert r.status_code == 400
