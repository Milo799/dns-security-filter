#!/usr/bin/env bash
# 一键本地启动开发环境（代理 + 平台）。
# 前置：make init（安装平台依赖）、代理需 Go 1.21+ 已构建或 make proxy。
# 注意：监听 53 需要 root / CAP_NET_BIND_SERVICE；本地开发可改用 5300 调试。

set -euo pipefail
cd "$(dirname "$0")/.."

PROXY_ADDR=${PROXY_ADDR:-127.0.0.1:5300}      # 本地调试端口（非 53，避免权限问题）
PLATFORM_DNS_PORT=${PLATFORM_DNS_PORT:-5353}
PLATFORM_WEB_PORT=${PLATFORM_WEB_PORT:-8080}

echo "==> 启动安全过滤平台（DNS:$PLATFORM_DNS_PORT / Web:$PLATFORM_WEB_PORT）"
# TODO(AI): 本地调试用临时配置覆盖端口；正式部署按 deploy/install.sh 用 systemd
(cd platform && \
 DNS_LISTEN_PORT=$PLATFORM_DNS_PORT python3 -m uvicorn app.main:app --host 127.0.0.1 --port $PLATFORM_WEB_PORT & \
 DNS_LISTEN_PORT=$PLATFORM_DNS_PORT python3 dns_server.py &)

sleep 2
echo "==> 平台健康检查: curl -s 127.0.0.1:$PLATFORM_WEB_PORT/api/health"
curl -s "http://127.0.0.1:$PLATFORM_WEB_PORT/api/health" || true

echo "==> 启动 DNS 代理中间件（监听 $PROXY_ADDR，转发至平台 $PLATFORM_DNS_PORT）"
# TODO(AI): 生成代理本地配置 config.yaml（upstream_addr=127.0.0.1, upstream_port=$PLATFORM_DNS_PORT）
mkdir -p bin
if [ ! -f bin/dns-proxy ]; then
  (cd proxy && go build -o ../bin/dns-proxy .)
fi
# 代理配置示例：见 proxy/proxy.example.yaml，本地调试请复制并修改端口后运行：
#   ./bin/dns-proxy -config proxy/config.yaml
echo "代理已就绪：bin/dns-proxy（手动启动：./bin/dns-proxy -config proxy/config.yaml）"
echo "验证命令：dig @127.0.0.1 -p $PROXY_ADDR example.com"
