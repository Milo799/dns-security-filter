#!/usr/bin/env bash
# 端到端验证：通过代理查询，确认"代理 → 平台 → 公网解析 → 回传"链路通。
# 用法：./scripts/verify.sh <代理IP> <代理端口> [测试域名]

set -euo pipefail
cd "$(dirname "$0")/.."

PROXY_IP=${1:-127.0.0.1}
PROXY_PORT=${2:-5300}
DOMAIN=${3:-example.com}

echo "==> 端到端验证：dig @$PROXY_IP -p $PROXY_PORT $DOMAIN A"
if command -v dig >/dev/null 2>&1; then
  dig @"$PROXY_IP" -p "$PROXY_PORT" "$DOMAIN" A +short
else
  # 无 dig 时用 Python 构造查询验证（dnslib）
  python3 - "$PROXY_IP" "$PROXY_PORT" "$DOMAIN" <<'PY'
import sys
from dnslib import DNSRecord, QTYPE, DNSHeader

ip, port, domain = sys.argv[1], int(sys.argv[2]), sys.argv[3]
q = DNSRecord(q=DNSRecord.q(domain, QTYPE.A))
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(q.pack(), (ip, port))
data, _ = s.recvfrom(4096)
resp = DNSRecord.parse(data)
print("RCODE:", resp.header.rcode)
for rr in resp.rr:
    print("ANSWER:", rr)
print("链路验证通过" if resp.header.rcode == 0 else "链路异常")
PY
fi

echo "==> 完成。若未返回 IP，检查：代理是否启动、平台 DNS 是否监听、upstream_dns 是否可达"
