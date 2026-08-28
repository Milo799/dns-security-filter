"""端到端测试：黑名单拦截 / 白名单放行 / 正常转发 / AAAA 过滤 / 日志写入。

在测试进程内起一个模拟公网上游（线程 UDP），直接调用 detectors.process_query
验证完整检测链路，不依赖外部服务与固定端口。

运行：cd platform && python -m pytest ../tests/test_e2e.py -v
"""

import socket
import threading
import uuid

import pytest
from dnslib import DNSRecord, QTYPE, RR, A, AAAA, RCODE

from config import CONFIG
from detectors import process_query
from app.db import db_cursor


class FakeUpstream:
    """线程 UDP 服务器：对 A 返回 93.184.216.34，对 AAAA 返回 2001:db8::1。"""

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
                elif req.q.qtype == QTYPE.AAAA:
                    reply.add_answer(RR(req.q.qname, QTYPE.AAAA, ttl=60,
                                        rdata=AAAA("2001:db8::1")))
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


@pytest.fixture
def clean_domain():
    """返回一个唯一域名，测试结束清理名单与日志。"""
    domain = f"e2e-{uuid.uuid4().hex[:8]}.test"
    yield domain
    with db_cursor() as cur:
        cur.execute("DELETE FROM filter_list WHERE value=?", (domain,))
        cur.execute("DELETE FROM filter_log WHERE domain=?", (domain,))


def _query(domain: str, qtype_str: str = "A") -> DNSRecord:
    req = DNSRecord.question(domain, qtype_str)
    return process_query(req, client_ip="192.168.1.100")


def _add_list(list_type: str, target: str, value: str):
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO filter_list (list_type, target, value, enabled) VALUES (?,?,?,1)",
            (list_type, target, value),
        )


def test_blacklist_domain_intercepted(upstream, clean_domain):
    _add_list("blacklist", "domain", clean_domain)
    resp = _query(clean_domain)
    assert resp.header.rcode == RCODE.NOERROR
    assert [str(r.rdata) for r in resp.rr] == [CONFIG.alert_ip]


def test_whitelist_overrides_blacklist(upstream, clean_domain):
    """白名单优先级最高：命中白名单跳过全部检测直接放行。"""
    _add_list("blacklist", "domain", clean_domain)
    _add_list("whitelist", "domain", clean_domain)
    resp = _query(clean_domain)
    assert [str(r.rdata) for r in resp.rr] == ["93.184.216.34"]


def test_wildcard_blacklist(upstream, clean_domain):
    """通配符 *.xxx.com 匹配子域。"""
    root = clean_domain
    _add_list("blacklist", "domain", "*." + root)
    resp = _query(f"a.b.{root}")
    assert [str(r.rdata) for r in resp.rr] == [CONFIG.alert_ip]


def test_normal_domain_forwarded(upstream, clean_domain):
    resp = _query(clean_domain)
    assert resp.header.rcode == RCODE.NOERROR
    assert [str(r.rdata) for r in resp.rr] == ["93.184.216.34"]


def test_aaaa_normal_domain_filtered(upstream, clean_domain):
    """AAAA 与 A 同等走过滤流程，正常放行返回 IPv6。"""
    resp = _query(clean_domain, "AAAA")
    assert [str(r.rdata) for r in resp.rr] == ["2001:db8::1"]


def test_aaaa_blacklist_intercept_empty(upstream, clean_domain):
    """AAAA 命中黑名单 → 空应答（NOERROR，无 ANSWER）。"""
    _add_list("blacklist", "domain", clean_domain)
    resp = _query(clean_domain, "AAAA")
    assert resp.header.rcode == RCODE.NOERROR
    assert len(resp.rr) == 0


def test_ip_cidr_blacklist_removes_ip(upstream, clean_domain):
    """IP 后置过滤：解析结果命中 IP 黑名单 CIDR → 全部剔除 → 拦截。"""
    _add_list("blacklist", "ip", "93.184.216.0/24")
    resp = _query(clean_domain)
    assert [str(r.rdata) for r in resp.rr] == [CONFIG.alert_ip]


def test_intercept_writes_filter_log(upstream, clean_domain):
    _add_list("blacklist", "domain", clean_domain)
    _query(clean_domain)
    import log_writer
    log_writer._flush_once()   # 异步日志落库后再查（前置项5）
    with db_cursor() as cur:
        cur.execute(
            "SELECT * FROM filter_log WHERE domain=? AND action='intercept'",
            (clean_domain,),
        )
        row = cur.fetchone()
    assert row is not None
    assert row["client_ip"] == "192.168.1.100"
    assert row["filter_reason"] == "local_blacklist"
    assert row["final_result"] == "alert_ip:" + CONFIG.alert_ip
