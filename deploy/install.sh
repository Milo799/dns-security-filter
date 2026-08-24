#!/usr/bin/env bash
# 生产部署骨架（Linux systemd）。
# 用法：sudo ./deploy/install.sh <安装目录，默认 /opt/dns-security-filter>
#
# 说明：本脚本为骨架，AI 开发完成后需按实际产物完善：
#   - 代理二进制路径 / 构建方式
#   - 平台 Python 依赖安装（venv 或系统包）
#   - 配置模板落位（proxy/config.yaml、platform/platform.yaml）
#   - 防火墙放行 53/UDP+TCP（平台与代理）与 8080/TCP（Web，建议仅内网）

set -euo pipefail
cd "$(dirname "$0")/.."

INSTALL_DIR=${1:-/opt/dns-security-filter}
APP_USER=${APP_USER:-dnsfilter}

echo "==> 安装目录：$INSTALL_DIR"
sudo mkdir -p "$INSTALL_DIR"/{bin,proxy,platform,data}
sudo cp -r proxy platform deploy "$INSTALL_DIR"/

# 1) 代理二进制（TODO: 替换为实际构建产物）
# (cd proxy && go build -o ../bin/dns-proxy .) && sudo cp bin/dns-proxy "$INSTALL_DIR/bin/"

# 2) 平台依赖（TODO: 建议 python3 -m venv）
# sudo python3 -m pip install -r "$INSTALL_DIR/platform/requirements.txt"

# 3) 配置文件模板（TODO: 按实际环境修改后落位）
# sudo cp proxy/proxy.example.yaml "$INSTALL_DIR/proxy/config.yaml"
# sudo cp platform/platform.example.yaml "$INSTALL_DIR/platform/platform.yaml"

# 4) systemd 服务
sudo useradd -r -s /usr/sbin/nologin "$APP_USER" 2>/dev/null || true
sudo cp deploy/proxy.service deploy/platform-dns.service deploy/platform-web.service /etc/systemd/system/
sudo systemctl daemon-reload

echo "==> 部署骨架就绪。接下来："
echo "    1. 构建/安装代理与平台依赖（见脚本 TODO）"
echo "    2. 配置转发器：Windows DNS 指向 代理IP:53"
echo "    3. 故障回退：Windows DNS 转发器改回公网 DNS（备份原配置）"
