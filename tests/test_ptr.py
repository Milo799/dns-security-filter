"""PTR 反向解析过滤测试。

- extract_ptr_ip：in-addr.arpa / ip6.arpa 查询名 → IP 解析
- process_query PTR 链路：黑名单拦截 / 白名单放行 / 正常转发 / 非标准名转发 / 日志
- 测试中心 API：POST /api/test/domain query_type=PTR（IP 或 PTR 名均可）

全部使用本地名单与进程内模拟上游，不依赖公网。
"""

import socket
import threading

import pytest
from dnslib import DNSRecord, QTYPE, RR, A, PTR, RCODE

from config import CONFIG
from detectors import process_query, extract_ptr_ip
from app.db import db_cursor


# ---------------- extract_ptr_ip 单元测试 ----------------

def test_extract_ptr_ipv4():
    assert extract_ptr_ip("4.3.2.1.in-addr.arpa") == "1.2.3.4"
    assert extract_ptr_ip("8.8.8.8.in-addr.arpa") == "8.8.8.8"
    assert extract_ptr_ip("0.0.0.10.in-addr.arpa") == "10.0.0.0"
    assert extract_ptr_ip("8.8.8.8.IN-ADDR.ARPA") == "8.8.8.8"  # 大小写不敏感


def test_extract_ptr_ipv6():
    # 2001:db8::567:89ab 的反查名（32 个半字节反转）
    name = ("b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0."
            "8.b.d.0.1.0.0.2.ip6.arpa")
    assert extract_ptr_ip(name) == "2001:db8::567:89ab"


def test_extract_ptr_invalid():
    assert extract_ptr_ip("example.com") is None
    assert extract_ptr_ip("1.2.3.in-addr.arpa") is None          # 段数不足
    assert extract_ptr_ip("256.2.3.4.in-addr.arpa") is None      # 越界
    assert extract_ptr_ip("a.b.c.d.in-addr.arpa") is None        # 非数字
    assert extract_ptr_ip("") is None
    assert extract_ptr_ip(None) is None


# ---------------- process_query PTR 链路 ----------------

class FakeUpstream:
    """线程 UDP 服务器：对 A 返回 93.184.216.34，对 PTR 返回一条 PTR 记录。"""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.3)
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                req = DNSRecord.parse(data)
                reply = req.reply()
                if req.q.qtype == QTYPE.A:
                    reply.add_answer(RR(req.q.qname, QTYPE.A, ttl=60,
                                        rdata=A("93.184.216.34")))
                elif req.q.qtype == QTYPE.PTR:
                    reply.add_answer(RR(req.q.qname, QTYPE.PTR, ttl=60,
                                        rdata=PTR("ptr-target.example.com.")))
                self.sock.sendto(reply.pack(), addr)
            except Exception:
                continue

    def close(self):
        self.running = False
        self.sock.close()


@pytest.fixture
def upstream():
    fu = FakeUpstream()
    old = CONFIG.upstream_dns
    CONFIG.upstream_dns = f"127.0.0.1:{fu.port}"
    yield fu
    CONFIG.upstream_dns = old
    fu.close()


def _add_list(list_type: str, target: str, value: str):
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO filter_list (list_type, target, value, enabled) VALUES (?,?,?,1)",
            (list_type, target, value),
        )


def _ptr_query(ptr_name: str) -> DNSRecord:
    return process_query(DNSRecord.question(ptr_name, "PTR"),
                         client_ip="192.168.1.100")


def _last_log(ptr_name: str):
    import log_writer
    log_writer._flush_once()   # 异步日志落库后再查（前置项5）
    with db_cursor() as cur:
        cur.execute("SELECT * FROM filter_log WHERE domain=? ORDER BY id DESC LIMIT 1",
                    (ptr_name,))
        return cur.fetchone()


def test_ptr_blacklist_ip_intercepted(upstream):
    _add_list("blacklist", "ip", "8.8.8.8")
    resp = _ptr_query("8.8.8.8.in-addr.arpa")
    assert resp.header.rcode == RCODE.NOERROR
    assert len(resp.rr) == 0                       # 拦截：空应答（无 PTR 记录）
    row = _last_log("8.8.8.8.in-addr.arpa")
    assert row is not None
    assert row["action"] == "intercept"
    assert row["query_type"] == "PTR"
    assert row["filter_reason"] == "local_blacklist"
    assert row["malicious_ips"] == "8.8.8.8"       # 记录的恶意 IP


def test_ptr_cidr_blacklist_intercepted(upstream):
    _add_list("blacklist", "ip", "9.9.9.0/24")
    # 注意：7.9.9.9.in-addr.arpa 反查的是 9.9.9.7（in-addr.arpa 为反转）
    resp = _ptr_query("7.9.9.9.in-addr.arpa")
    assert len(resp.rr) == 0


def test_ptr_whitelist_overrides_blacklist(upstream):
    _add_list("blacklist", "ip", "8.8.4.4")
    _add_list("whitelist", "ip", "8.8.4.4")
    resp = _ptr_query("8.8.4.4.in-addr.arpa")
    assert resp.header.rcode == RCODE.NOERROR
    assert len(resp.rr) == 1                       # 放行：上游 PTR 应答原样返回
    assert resp.rr[0].rtype == QTYPE.PTR


def test_ptr_clean_forwarded(upstream):
    resp = _ptr_query("1.2.3.4.in-addr.arpa")
    assert resp.header.rcode == RCODE.NOERROR
    assert len(resp.rr) == 1
    assert _last_log("1.2.3.4.in-addr.arpa") is None  # 未拦截不写日志


def test_ptr_non_standard_name_forwarded(upstream):
    """非标准 PTR 名（无法提取 IP）→ 直接转发，不误拦。"""
    resp = _ptr_query("not-a-ptr-name.example.com")
    assert resp.header.rcode == RCODE.NOERROR
    assert len(resp.rr) == 1


# ---------------- 测试中心 API（PTR） ----------------

@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def token(client):
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": "admin123"})
    return r.json()["data"]["token"]


def _h(token):
    return {"Authorization": f"Bearer {token}"}


def test_api_ptr_clean_forward(client, token):
    r = client.post("/api/test/domain", json={"domain": "1.1.1.1",
                                              "query_type": "PTR"},
                    headers=_h(token))
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["query_type"] == "PTR"
    assert d["ptr_ip"] == "1.1.1.1"
    assert d["domain"] == "1.1.1.1.in-addr.arpa"   # 输入 IP 自动转 PTR 名
    assert d["final_verdict"]["action"] == "forward"


def test_api_ptr_blacklist_intercept(client, token):
    client.post("/api/list",
                json={"list_type": "blacklist", "target": "ip",
                      "value": "2.2.2.2", "enabled": True},
                headers=_h(token))
    r = client.post("/api/test/domain", json={"domain": "2.2.2.2",
                                              "query_type": "PTR"},
                    headers=_h(token))
    d = r.json()["data"]
    assert d["local_blacklist"]["matched"] is True
    assert d["final_verdict"]["action"] == "intercept"


def test_api_ptr_accepts_ptr_name(client, token):
    """直接输入 in-addr.arpa 查询名亦可。"""
    r = client.post("/api/test/domain",
                    json={"domain": "3.3.3.3.in-addr.arpa",
                          "query_type": "PTR"},
                    headers=_h(token))
    d = r.json()["data"]
    assert d["ptr_ip"] == "3.3.3.3"
    assert d["final_verdict"]["action"] == "forward"


def test_api_ptr_whitelist_allow(client, token):
    client.post("/api/list",
                json={"list_type": "whitelist", "target": "ip",
                      "value": "5.5.5.5", "enabled": True},
                headers=_h(token))
    client.post("/api/list",
                json={"list_type": "blacklist", "target": "ip",
                      "value": "5.5.5.5", "enabled": True},
                headers=_h(token))
    r = client.post("/api/test/domain", json={"domain": "5.5.5.5",
                                              "query_type": "PTR"},
                    headers=_h(token))
    d = r.json()["data"]
    assert d["whitelist"]["matched"] is True
    assert d["final_verdict"]["action"] == "allow"


def test_api_ptr_invalid_400(client, token):
    r = client.post("/api/test/domain", json={"domain": "not-an-ip",
                                              "query_type": "PTR"},
                    headers=_h(token))
    assert r.status_code == 400
    r = client.post("/api/test/domain", json={"domain": "x.com",
                                              "query_type": "TXT"},
                    headers=_h(token))
    assert r.status_code == 400
