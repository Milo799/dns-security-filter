"""拦截应答构造测试（detectors.build_intercept_reply）。

覆盖 PRD 5.4：A 查询返回告警 IP；AAAA 查询返回空应答（NOERROR）。
"""

from dnslib import DNSRecord, QTYPE, A, AAAA, RCODE

from detectors import build_intercept_reply
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
