"""拦截应答构造测试（detectors.build_intercept_reply）。

覆盖 PRD 5.4：A 查询返回告警 IP；AAAA 查询返回空应答（NOERROR）。
"""

import struct

import pytest
from dnslib import DNSRecord, QTYPE, A, AAAA, RCODE
from dnslib.dns import DNSError

import circuit_breaker
from detectors import build_intercept_reply, query_upstream_reply, _rebuild_passthrough
from config import CONFIG


def make_request(qtype_str: str) -> DNSRecord:
    # dnslib 的 DNSRecord.question 需字符串类型名（如 "A"/"AAAA"）
    return DNSRecord.question("evil.example.com", qtype_str)


def test_a_intercept_returns_alert_ip():
    reply = build_intercept_reply(make_request("A"), QTYPE.A)
    assert reply.header.rcode == RCODE.NOERROR
    answers = reply.rr
    assert len(answers) == 1
    assert str(answers[0].rdata) == CONFIG.alert_ip
    assert answers[0].ttl == CONFIG.alert_ttl


def test_aaaa_intercept_returns_empty():
    reply = build_intercept_reply(make_request("AAAA"), QTYPE.AAAA)
    assert reply.header.rcode == RCODE.NOERROR
    assert len(reply.rr) == 0  # 空应答：客户端无 IPv6 可用


# ---------------------------------------------------------------------------
# 迭代 44：NAPTR dnslib 解析失败透传降级
# ---------------------------------------------------------------------------

# 模拟一个上游真实应答但 dnslib 无法解析的 NAPTR 报文
#（压缩指针指向记录内偏移量，触发 dnslib "Invalid pointer in DNSLabel"）
_MOCK_NAPTR_HEADER = struct.pack(
    ">6H",
    0x1234,              # id
    0x8580,              # flags: QR=1, OPCODE=0, AA=1, RD=1, RA=1, RCODE=0
    1,                   # qdcount
    1,                   # ancount
    0,                   # nscount
    0,                   # arcount
)


def _build_mock_naptr_wire() -> bytes:
    """构造上游原始 NAPTR 应答 wire data（dnslib 会解析失败）。"""
    # question section: example.com NAPTR
    qname = b"".join(bytes([len(x)]) + x.encode()
                     for x in "example.com".split(".")) + b"\x00"
    question = qname + struct.pack(">HH", 35, 1)   # QTYPE=NAPTR(35), QCLASS=IN
    # answer section：压缩指针指向 12（question 起点）——
    # dnslib 解析 NAPTR rdata 时会报 Invalid pointer in DNSLabel
    rdata = struct.pack(">HH", 100, 10) + b"\x00" + b"sip.example.com\x00"
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 35, 1, 300, len(rdata)) + rdata
    return _MOCK_NAPTR_HEADER + question + answer


def test_rebuild_passthrough_preserves_wire_bytes():
    """透传降级：header/question 正确、pack 直接返回上游原始 bytes。"""
    req = DNSRecord.question("example.com", "NAPTR")
    wire = _build_mock_naptr_wire()
    reply = _rebuild_passthrough(req, wire)
    # header 从上游原始 bytes 提取
    assert reply.header.id == 0x1234
    assert reply.header.rcode == RCODE.NOERROR
    assert reply.header.ancount == 1
    # question 保留
    assert str(reply.q.qname) == "example.com."
    assert reply.q.qtype == QTYPE.NAPTR
    # pack 直接返回原始 bytes（跳过 dnslib 二次解析）
    assert reply.pack() == wire


def test_rebuild_passthrough_rejects_short_wire():
    """过短的上游报文（<12 字节 header）直接抛异常放弃降级。"""
    req = DNSRecord.question("example.com", "NAPTR")
    with pytest.raises(ValueError, match="过短"):
        _rebuild_passthrough(req, b"\x00\x01\x02")


def test_query_upstream_reply_passthrough_on_dnslib_error(monkeypatch):
    """query_upstream_reply 捕获 dnslib 解析异常时透传降级而非 SERVFAIL。"""
    wire = _build_mock_naptr_wire()
    req = DNSRecord.question("example.com", "NAPTR")

    # 模拟上游 send 返回 wire data，但 DNSRecord.parse 抛 dnslib 异常
    class _FakeSender:
        def send(self, host, port, timeout=None):
            return wire

    monkeypatch.setattr(DNSRecord, "send", _FakeSender().send)

    def _parse_raises(data):
        raise DNSError("Invalid pointer in DNSLabel [offset=74]")

    monkeypatch.setattr(DNSRecord, "parse", staticmethod(_parse_raises))

    # 上游熔断初始为 closed
    circuit_breaker.reset_all()
    reply = query_upstream_reply(req)
    # 透传成功：不是 SERVFAIL，pack 返回原始 bytes
    assert reply.header.rcode == RCODE.NOERROR
    assert reply.pack() == wire
    # 熔断计为成功（上游健康，是 dnslib 缺陷）
    assert circuit_breaker.upstream_state()["state"] == "closed"
