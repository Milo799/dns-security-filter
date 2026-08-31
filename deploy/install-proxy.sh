#!/usr/bin/env bash
# ============================================================================
# DNS 安全过滤 · 机 A（代理节点）一键安装脚本
# ============================================================================
# 用法（在仓库根目录执行）：
#   sudo ./deploy/install-proxy.sh --upstream 192.168.10.21
#
#   完整参数（均有默认值，见下）：
#     --upstream        IP      平台（机B）内网 IP          默认 127.0.0.1
#     --upstream-port   NUM     平台 DNS 端口               默认 15353
#     --listen-port     NUM     本机代理监听端口            默认 53
#     --forward-timeout NUM     转发超时秒数                默认 8
#     --binary          PATH    预编译代理二进制路径        默认 bin/dns-proxy
#     --install-dir     DIR     安装目录                    默认 /opt/dns-security-filter
#     --skip-tuning             跳过 sysctl/limits 内核参数调优
#
# 脚本做 8 件事（全部幂等，可重复执行）：
#   1 环境检测（root / Linux / 53 端口占用提示）
#   2 创建 dnsfilter 系统用户与目录
#   3 安装代理二进制 + setcap 53 端口授权
#   4 从 proxy.example.yaml 生成带全量注释的 config.yaml（已存在则保留）
#   5 安装并启动 systemd 服务 proxy
#   6 内核参数调优（DNS 高并发收发缓冲）
#   7 文件句柄上限
#   8 自检（服务状态 / 端口监听）
# ============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ---- 默认值 ----------------------------------------------------------------
UPSTREAM="127.0.0.1"
UPSTREAM_PORT=15353
LISTEN_PORT=53
FORWARD_TIMEOUT=8
BINARY="$REPO_ROOT/bin/dns-proxy"
INSTALL_DIR="/opt/dns-security-filter"
SKIP_TUNING=0
APP_USER="dnsfilter"

# ---- 参数解析 --------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --upstream)        UPSTREAM="$2"; shift 2 ;;
    --upstream-port)   UPSTREAM_PORT="$2"; shift 2 ;;
    --listen-port)     LISTEN_PORT="$2"; shift 2 ;;
    --forward-timeout) FORWARD_TIMEOUT="$2"; shift 2 ;;
    --binary)          BINARY="$2"; shift 2 ;;
    --install-dir)     INSTALL_DIR="$2"; shift 2 ;;
    --skip-tuning)     SKIP_TUNING=1; shift ;;
    -h|--help)         grep '^#' "$0" | sed 's/^# \{0,2\}//'; exit 0 ;;
    *) echo "未知参数: $1（--help 查看用法）" >&2; exit 1 ;;
  esac
done

log()  { echo -e "\033[1;32m==>\033[0m $*"; }
warn() { echo -e "\033[1;33m[警告]\033[0m $*" >&2; }
die()  { echo -e "\033[1;31m[错误]\033[0m $*" >&2; exit 1; }

# ---- 1 环境检测 ------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "请用 root 运行：sudo $0"
[[ "$(uname -s)" == "Linux" ]] || die "本脚本仅支持 Linux（当前 $(uname -s)）"

# systemd-resolved 占用 53 的常见坑（Ubuntu 默认开启 127.0.0.53 stub）
if command -v ss >/dev/null 2>&1 && [[ "$LISTEN_PORT" == "53" ]]; then
  if ss -lun 2>/dev/null | grep -q ':53 '; then
    warn "UDP 53 已被占用（最常见是 systemd-resolved 的 127.0.0.53 stub）："
    ss -lun | grep ':53 ' | sed 's/^/      /' >&2
    warn "让出 53 端口的方法："
    warn "  sudo mkdir -p /etc/systemd/resolved.conf.d"
    warn "  printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/no-stub.conf"
    warn "  sudo systemctl restart systemd-resolved"
  fi
fi

# ---- 2 用户与目录 -----------------------------------------------------------
id "$APP_USER" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$APP_USER"
mkdir -p "$INSTALL_DIR/bin" "$INSTALL_DIR/proxy"
log "安装目录：$INSTALL_DIR（运行用户：$APP_USER）"

# ---- 3 二进制 + 端口授权 ----------------------------------------------------
[[ -x "$BINARY" ]] || die "代理二进制不存在：$BINARY
  请先在任意有 Go>=1.21 的机器上交叉编译并放到该路径：
    cd proxy && GOPROXY=https://goproxy.cn,direct GOOS=linux GOARCH=amd64 go build -o ../bin/dns-proxy .
  或用 --binary 指定已上传的二进制位置（如 /tmp/dns-proxy）"
install -m 0755 "$BINARY" "$INSTALL_DIR/bin/dns-proxy"
if [[ "$LISTEN_PORT" -lt 1024 ]]; then
  setcap 'cap_net_bind_service=+ep' "$INSTALL_DIR/bin/dns-proxy"
  log "已授权 $APP_USER 用户绑定特权端口 $LISTEN_PORT（setcap）"
fi

# ---- 4 配置生成（替换键值、保留全量注释；已存在则保留不动）------------------
CONFIG="$INSTALL_DIR/proxy/config.yaml"
if [[ -f "$CONFIG" ]]; then
  warn "配置已存在，保留不覆盖：$CONFIG（如需重新生成请先备份删除）"
else
  sed -E \
    -e "s|^(listen_port:)[[:space:]]*[0-9]+|\1 $LISTEN_PORT|" \
    -e "s|^(upstream_addr:)[[:space:]]*[^# ]+|\1 $UPSTREAM|" \
    -e "s|^(upstream_port:)[[:space:]]*[0-9]+|\1 $UPSTREAM_PORT|" \
    -e "s|^(forward_timeout:)[[:space:]]*[0-9]+|\1 $FORWARD_TIMEOUT|" \
    "$REPO_ROOT/proxy/proxy.example.yaml" > "$CONFIG"
  chmod 0640 "$CONFIG"
  log "已生成配置 $CONFIG（listen=:$LISTEN_PORT upstream=$UPSTREAM:$UPSTREAM_PORT timeout=${FORWARD_TIMEOUT}s）"
fi

# ---- 5 systemd 服务 --------------------------------------------------------
sed -E "s|/opt/dns-security-filter|$INSTALL_DIR|g" \
    "$REPO_ROOT/deploy/proxy.service" > /etc/systemd/system/proxy.service
systemctl daemon-reload
systemctl enable proxy >/dev/null 2>&1
systemctl restart proxy
log "服务 proxy 已安装并启动（开机自启）"

# ---- 6/7 内核参数与句柄上限（幂等追加）-------------------------------------
if [[ $SKIP_TUNING -eq 0 ]]; then
  touch /etc/sysctl.d/99-dnsfilter.conf
  for kv in "net.core.rmem_max=16777216" "net.core.wmem_max=16777216" "net.core.netdev_max_backlog=10000"; do
    key="${kv%%=*}"; want="${kv#*=}"
    cur=$(sysctl -n "$key" 2>/dev/null || echo 0)
    [[ "${cur:-0}" -lt "$want" ]] && echo "$kv" >> /etc/sysctl.d/99-dnsfilter.conf
  done
  # 同 key 多次追加时取最后一次（tac 去重保末值）
  tac /etc/sysctl.d/99-dnsfilter.conf | awk '!seen[$1]++' | tac > /etc/sysctl.d/99-dnsfilter.conf.tmp && \
    mv /etc/sysctl.d/99-dnsfilter.conf.tmp /etc/sysctl.d/99-dnsfilter.conf
  sysctl --system >/dev/null 2>&1 || true
  if ! grep -q "^${APP_USER} soft nofile" /etc/security/limits.conf 2>/dev/null; then
    echo "${APP_USER} soft nofile 65536" >> /etc/security/limits.conf
    echo "${APP_USER} hard nofile 65536" >> /etc/security/limits.conf
  fi
  log "内核参数（收发缓冲/backlog）与句柄上限已就绪"
fi

# ---- 8 自检 -----------------------------------------------------------------
sleep 2
systemctl is-active --quiet proxy || { journalctl -u proxy -n 20 --no-pager; die "服务未正常运行，上方为最近日志"; }
log "自检通过：proxy 服务运行中"
if command -v ss >/dev/null 2>&1; then
  ss -lun | grep -q ":${LISTEN_PORT} " && log "自检通过：UDP $LISTEN_PORT 已监听" || warn "UDP $LISTEN_PORT 暂未监听（可能启动中，稍后 ss -lun 复查）"
fi

chown -R "$APP_USER:$APP_USER" "$INSTALL_DIR"

LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[[ -n "$LOCAL_IP" ]] || LOCAL_IP=$(ip -4 route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="src")print $(i+1)}' | head -1)

echo
log "机 A（代理）安装完成。后续两步："
echo "  1) 防火墙：仅放行各域控（DC）IP 访问本机 ${LISTEN_PORT}/UDP+TCP"
echo "  2) 域控转发器：每台 DC 的 DNS 转发器指向 ${LOCAL_IP:-本机IP}:${LISTEN_PORT}（先灰度 1 台）"
echo "     改配置：$CONFIG（含逐项注释说明，改后 systemctl restart proxy）"
