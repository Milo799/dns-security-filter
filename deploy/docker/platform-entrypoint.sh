#!/bin/sh
# DNS 安全过滤平台容器入口：
#   - 后台启动 DNS 服务（dns_server.py，UDP/TCP 53）
#   - 前台启动 Web 服务（uvicorn，端口由 WEB_PORT 控制，默认 8080）
# 任一进程异常退出，容器随之退出（便于 docker restart / 编排重启）。
set -e

echo "[entrypoint] 启动 DNS 服务（dns_server.py）..."
python /app/platform/dns_server.py &
DNS_PID=$!

echo "[entrypoint] 启动 Web 服务（uvicorn，端口 ${WEB_PORT:-8080}）..."
cd /app/platform
uvicorn app.main:app --host 0.0.0.0 --port "${WEB_PORT:-8080}" &
WEB_PID=$!

# 任一进程退出即终止整体，避免孤儿进程
trap 'kill $DNS_PID $WEB_PID 2>/dev/null || true' TERM INT
wait -n $DNS_PID $WEB_PID
kill $DNS_PID $WEB_PID 2>/dev/null || true
exit 1
