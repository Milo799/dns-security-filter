#!/usr/bin/env python3
"""本地模拟公网 DNS 上游（测试/演示工具）。

对任何 A/AAAA 查询返回固定 IP（默认 93.184.216.34），
用于在无外网环境验证"平台 → 上游解析 → 原样返回"链路，以及 e2e 测试。

用法：
    python scripts/fake_upstream.py [port] [answer_ip]
"""

import socket
import sys

from dnslib import DNSRecord, QTYPE, RR, A, AAAA, RCODE

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 15354
ANSWER_IP = sys.argv[2] if len(sys.argv) > 2 else "93.184.216.34"


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", PORT))
    print(f"模拟上游已启动: 127.0.0.1:{PORT} → 应答 {ANSWER_IP}")
    while True:
        data, addr = s.recvfrom(4096)
        try:
            req = DNSRecord.parse(data)
            reply = req.reply()
            qtype = req.q.qtype
            if qtype == QTYPE.A:
                reply.add_answer(RR(req.q.qname, QTYPE.A, ttl=60, rdata=A(ANSWER_IP)))
            elif qtype == QTYPE.AAAA:
                reply.add_answer(RR(req.q.qname, QTYPE.AAAA, ttl=60,
                                    rdata=AAAA("2001:db8::1")))
            s.sendto(reply.pack(), addr)
            print(f"应答 {req.q.qname} {qtype}")
        except Exception as e:
            print(f"处理异常: {e}")


if __name__ == "__main__":
    main()
