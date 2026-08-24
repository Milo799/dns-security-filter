"""EDNS0 Client Subnet（RFC 7871）解析测试。

手工构造 DNS 查询 wire format（含 OPT RR + ECS option），
验证 dns_server.extract_client_ip 的解析正确性与容错。
"""

import struct
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "platform"))

from dns_server import extract_client_ip  # noqa: E402


def build_query(domain: str = "www.example.com", qtype: int = 1,
                ecs: tuple[int, int, bytes] | None = None) -> bytes:
    """构造 DNS 查询报文。ecs = (family, src_prefix, address_bytes)。"""
    question = b""
    for label in domain.split("."):
        question += bytes([len(label)]) + label.encode()
    question += b"\x00" + struct.pack(">HH", qtype, 1)

    arcount = 1 if ecs else 0
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, arcount)
    if ecs is None:
        return header + question

    family, prefix, addr = ecs
    opt_data = struct.pack(">HBB", family, prefix, 0) + addr
    rdata = struct.pack(">HH", 8, len(opt_data)) + opt_data
    # OPT RR：根名(0x00) + type(41) + udpsize(4096) + ttl(0) + rdlen + rdata
    opt_rr = b"\x00" + struct.pack(">HHIH", 41, 4096, 0, len(rdata)) + rdata
    return header + question + opt_rr


def test_no_ecs_returns_none():
    assert extract_client_ip(build_query()) is None


def test_ipv4_ecs_slash24():
    # 192.168.10.0/24 → 地址按前缀截断为 3 字节，应还原为 192.168.10.0
    data = build_query(ecs=(1, 24, bytes([192, 168, 10])))
    assert extract_client_ip(data) == "192.168.10.0"


def test_ipv4_ecs_slash32():
    data = build_query(ecs=(1, 32, bytes([10, 20, 30, 40])))
    assert extract_client_ip(data) == "10.20.30.40"


def test_ipv6_ecs():
    # 2001:db8::/32 → 地址截断为 4 字节
    data = build_query(ecs=(2, 32, bytes([0x20, 0x01, 0x0d, 0xb8])))
    assert extract_client_ip(data) == "2001:db8::"


def test_ipv6_ecs_full():
    data = build_query(ecs=(2, 128, bytes.fromhex("20010db8000000000000000000000001")))
    assert extract_client_ip(data) == "2001:db8::1"


def test_ecs_with_non_ecs_option_first():
    """OPT 中先放一个其他 option（code=10 COOKIE），ECS 在其后仍能取到。"""
    question = b"\x03www\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
    cookie = struct.pack(">HH", 10, 4) + b"ABCD"
    ecs_data = struct.pack(">HBB", 1, 24, 0) + bytes([192, 168, 1])
    ecs_opt = struct.pack(">HH", 8, len(ecs_data)) + ecs_data
    rdata = cookie + ecs_opt
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 1)
    opt_rr = b"\x00" + struct.pack(">HHIH", 41, 4096, 0, len(rdata)) + rdata
    assert extract_client_ip(header + question + opt_rr) == "192.168.1.0"


def test_malformed_packets_return_none():
    assert extract_client_ip(b"") is None
    assert extract_client_ip(b"\x00" * 5) is None
    # 声称 1 个 question 但报文截断
    assert extract_client_ip(struct.pack(">HHHHHH", 1, 0x0100, 5, 0, 0, 0)) is None


def test_dnslib_roundtrip_with_ecs():
    """dnslib 能解析我们构造的含 ECS 报文（代理透传场景兼容性）。"""
    from dnslib import DNSRecord
    data = build_query(ecs=(1, 24, bytes([172, 16, 5])))
    rec = DNSRecord.parse(data)          # 不抛异常
    assert str(rec.q.qname) == "www.example.com."
    assert extract_client_ip(data) == "172.16.5.0"
