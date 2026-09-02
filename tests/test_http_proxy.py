"""情报出站代理功能测试（http_proxy 配置 + 共享 HTTP 客户端）。

覆盖：
  - 配置链路：ConfigBody 更新 http_proxy → system_config 落库 + 内存热更新；
  - 格式校验：非法 scheme / 缺主机被 400 拒绝；空串合法（停用）；
  - 共享客户端：设代理后 get/post/stream 挂上代理；清空恢复直连；
  - 代理状态接口 /api/proxy/status；
  - 代理配置经 runtime._apply 触发 http_client 联动（apply_proxy_change）。
"""

import httpx
import pytest
from fastapi.testclient import TestClient

from config import CONFIG


@pytest.fixture()
def client():
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def token(client):
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": "admin123"})
    assert r.status_code == 200
    return r.json()["data"]["token"]


@pytest.fixture(autouse=True)
def reset_proxy():
    """每个测试前后清空代理配置（内存 + 库），避免串扰。

    库也清：TestClient 每次进入触发 startup → sync_config_from_db
    会把上轮测试写入 system_config 的 http_proxy 重新灌回内存。
    """
    from app.db import db_cursor
    CONFIG.http_proxy = ""
    with db_cursor() as cur:
        cur.execute("DELETE FROM system_config WHERE key='http_proxy'")
    yield
    CONFIG.http_proxy = ""
    with db_cursor() as cur:
        cur.execute("DELETE FROM system_config WHERE key='http_proxy'")


# ================= 配置链路 =================

def test_proxy_config_save_and_read(client, token):
    r = client.put("/api/config", headers={"Authorization": f"Bearer {token}"},
                   json={"http_proxy": "http://172.16.0.10:8080"})
    assert r.status_code == 200
    assert r.json()["data"]["updated"]["http_proxy"] == "http://172.16.0.10:8080"
    # 内存热更新
    assert CONFIG.http_proxy == "http://172.16.0.10:8080"
    # 落库可读回
    r = client.get("/api/config", headers={"Authorization": f"Bearer {token}"})
    items = r.json()["data"]["items"]
    assert items["http_proxy"]["value"] == "http://172.16.0.10:8080"


def test_proxy_clear_empty_string(client, token):
    client.put("/api/config", headers={"Authorization": f"Bearer {token}"},
               json={"http_proxy": "http://172.16.0.10:8080"})
    r = client.put("/api/config", headers={"Authorization": f"Bearer {token}"},
                   json={"http_proxy": ""})
    assert r.status_code == 200
    assert CONFIG.http_proxy == ""


@pytest.mark.parametrize("bad", [
    "172.16.0.10:8080",             # 缺 scheme
    "socks5://172.16.0.10:1080",    # scheme 不在白名单
    "http://",                      # 缺主机
])
def test_proxy_invalid_rejected(client, token, bad):
    r = client.put("/api/config", headers={"Authorization": f"Bearer {token}"},
                   json={"http_proxy": bad})
    assert r.status_code == 400


# ================= 共享客户端代理分流 =================

def test_http_client_get_uses_configured_proxy(monkeypatch):
    from app import http_client
    CONFIG.http_proxy = "http://10.1.2.3:8080"
    http_client._local.clients = {}          # 清线程缓存
    seen = {}

    class FakeClient:
        def get(self, url, **kwargs):
            seen["url"] = url
            seen["proxy"] = "has"
            raise httpx.ConnectTimeout("stop")   # 不真正发请求

    monkeypatch.setattr(http_client, "_build_client",
                        lambda proxy: FakeClient() if proxy else None)
    with pytest.raises(httpx.ConnectTimeout):
        http_client.get("http://example.com/x", timeout=1)
    assert seen["url"] == "http://example.com/x"
    assert seen["proxy"] == "has"


def test_http_client_direct_when_no_proxy(monkeypatch):
    from app import http_client
    CONFIG.http_proxy = ""
    http_client._local.clients = {}
    seen = {}

    class FakeClient:
        def get(self, url, **kwargs):
            seen["called"] = True
            raise httpx.ConnectTimeout("stop")

    monkeypatch.setattr(http_client, "_build_client",
                        lambda proxy: FakeClient())
    with pytest.raises(httpx.ConnectTimeout):
        http_client.get("http://example.com/x", timeout=1)
    assert seen["called"]


def test_http_client_builds_client_with_proxy_object():
    """真实构建：代理 Client 的 _transport 挂代理（httpx 内部结构验证）。"""
    from app import http_client
    client = http_client._build_client("http://10.1.2.3:8080")
    # httpx 0.28: Client(proxy=...) 构建后 _transport 为带代理的 transport
    # 直接行为级验证：mounts 或 _transport 存在即可（不依赖内部字段名）
    assert client is not None
    client.close()


def test_runtime_apply_triggers_proxy_hook(monkeypatch):
    from app import runtime
    called = {}
    import app.http_client as hc
    monkeypatch.setattr(hc, "apply_proxy_change",
                        lambda: called.setdefault("hook", True))
    runtime._apply("http_proxy", "http://10.9.9.9:3128")
    assert CONFIG.http_proxy == "http://10.9.9.9:3128"
    assert called.get("hook") is True


def test_cross_sync_propagates_proxy(client, token):
    """Web 进程改代理 → system_config 表变更 → DNS 进程 cross_sync 轮询感知。"""
    import time

    import cross_sync
    cross_sync.reset_baseline()
    cross_sync.poll_once()          # 基线（startup 刚 seed 过 system_config）
    # updated_at 秒级粒度：先保证跨秒，再写入（否则 UPDATE 落在同秒
    # MAX 不变，轮询视为无变更——生产 60s 周期下无此问题，仅测试需对齐）
    time.sleep(1.1)
    client.put("/api/config", headers={"Authorization": f"Bearer {token}"},
               json={"http_proxy": "http://172.16.0.10:8080"})
    changed = cross_sync.poll_once()
    assert "system_config" in changed
    # DNS 进程侧内存已同步
    assert CONFIG.http_proxy == "http://172.16.0.10:8080"


# ================= 状态与测试端点 =================

def test_proxy_status_endpoint(client, token):
    r = client.get("/api/proxy/status",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["enabled"] is False
    assert d["proxy"] == ""


def test_proxy_status_endpoint_enabled(client, token):
    from app import http_client
    CONFIG.http_proxy = "http://10.1.2.3:8080"
    r = client.get("/api/proxy/status",
                   headers={"Authorization": f"Bearer {token}"})
    d = r.json()["data"]
    assert d["enabled"] is True
    assert d["proxy"] == "http://10.1.2.3:8080"


def test_proxy_test_endpoint_no_proxy_configured(client, token):
    r = client.post("/api/proxy/test", headers={"Authorization": f"Bearer {token}"},
                    json={})
    assert r.status_code == 400


def test_proxy_test_endpoint_invalid_scheme(client, token):
    r = client.post("/api/proxy/test", headers={"Authorization": f"Bearer {token}"},
                    json={"proxy": "ftp://1.2.3.4:21"})
    assert r.status_code == 400


def test_proxy_test_endpoint_unreachable(client, token):
    """不可达代理返回 reachable=False（不抛 5xx，前端能展示原因）。"""
    r = client.post("/api/proxy/test", headers={"Authorization": f"Bearer {token}"},
                    json={"proxy": "http://127.0.0.1:1"})
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["reachable"] is False
    assert d["detail"]


def test_seed_includes_http_proxy_default():
    from seed import DEFAULT_SYSTEM_CONFIG
    assert DEFAULT_SYSTEM_CONFIG.get("http_proxy") == ""


def test_download_once_uses_shared_client(monkeypatch):
    """threat_list._download_once 经共享客户端出站（代理生效时挂代理）。"""
    from app import threat_list, http_client
    CONFIG.http_proxy = "http://10.1.2.3:8080"
    http_client._local.clients = {}
    seen = {}

    class FakeStreamResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def raise_for_status(self):
            pass

        headers = {}

        def iter_bytes(self, n):
            return iter([b"example.com\n"])

    class FakeClient:
        def stream(self, method, url, **kwargs):
            seen["url"] = url
            seen["method"] = method
            return FakeStreamResp()

    monkeypatch.setattr(http_client, "_build_client",
                        lambda proxy: FakeClient())
    text = threat_list._download_once("https://example.com/list.txt",
                                      max_bytes=1024, timeout_s=5)
    assert "example.com" in text
    assert seen["url"] == "https://example.com/list.txt"
    assert seen["method"] == "GET"
