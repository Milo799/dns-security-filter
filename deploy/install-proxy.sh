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
#     --binary          PATH    指定代理二进制（跳过源码编译）
#                               不指定时：有 Go 工具链就从源码现编（首选）
#     --allow-stale             放行"与源码不一致的旧产物"（仅排障，慎用）
#     --install-dir     DIR     安装目录                    默认 /opt/dns-security-filter
#     --skip-tuning             跳过 sysctl 内核参数调优
#
# 脚本做 7 件事（全部幂等，可重复执行）：
#   1 环境检测（root / Linux / 53 端口占用提示）
#   2 创建安装目录
#   3 编译/安装代理二进制 + **与源码一致性校验**（拒绝旧产物，见下）
#   4 从 proxy.example.yaml 生成带全量注释的 config.yaml（已存在则保留）
#   5 安装并启动 systemd 服务 proxy
#   6 内核参数调优（DNS 高并发收发缓冲；句柄由 systemd LimitNOFILE 承担）
#   7 自检（服务状态 / 端口监听）
#
# ⚠️ 第 3 步的校验是事故后加固（2026-10-14）：此前本脚本无条件安装
#    bin/dns-proxy（gitignore 的构建产物）。09-02 编译后源码更新到含
#    proxy/ecs.go 的版本，09-04 重跑脚本时又把旧产物装了一遍——生产代理
#    因此缺"客户端 IP 注入"，平台侧 client_ip 长期全空且无任何报错
#    （排查 4 层才定位到部署层）。根因=交付物与源码脱钩，现已固化为硬校验。
# ============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ---- 默认值 ----------------------------------------------------------------
UPSTREAM="127.0.0.1"
UPSTREAM_PORT=15353
LISTEN_PORT=53
FORWARD_TIMEOUT=8
BINARY_ARG=""                 # 用户显式 --binary（空=从源码现编）
ALLOW_STALE=0
INSTALL_DIR="/opt/dns-security-filter"
SKIP_TUNING=0
# 服务以 root 运行（内网专用设备 + 上联 ACL 边界防护形态）：
# 绑定 53 特权端口无需 setcap，也免去专用用户属主管理

# ---- 参数解析 --------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --upstream)        UPSTREAM="$2"; shift 2 ;;
    --upstream-port)   UPSTREAM_PORT="$2"; shift 2 ;;
    --listen-port)     LISTEN_PORT="$2"; shift 2 ;;
    --forward-timeout) FORWARD_TIMEOUT="$2"; shift 2 ;;
    --binary)          BINARY_ARG="$2"; shift 2 ;;
    --allow-stale)     ALLOW_STALE=1; shift ;;
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

# ---- 2 目录 ------------------------------------------------------------------
mkdir -p "$INSTALL_DIR/bin" "$INSTALL_DIR/proxy"
log "安装目录：$INSTALL_DIR（服务以 root 运行）"

# ---- 3 二进制（★ 必须与当前源码一致）----------------------------------------
# 事故复盘（2026-10-14）：本脚本原先无条件安装 bin/dns-proxy——那是 gitignore
# 的构建产物。09-02 编译后源码更新到含 proxy/ecs.go 的版本（Task#158 客户端
# IP 注入），09-04 重跑脚本时又把旧产物装了一遍，生产代理因此缺该能力，
# 平台侧 client_ip 长期全空且无任何报错。根因=交付物与源码脱钩。
# 规则：①不指定 --binary → 有 Go 就从源码现编（首选）；②无论哪条路径都校验
# "产物不比源码旧"+ "版本戳与仓库 HEAD 一致"；③不一致即中止，确需旧产物用
# --allow-stale 显式放行。
BINARY="${BINARY_ARG:-$REPO_ROOT/bin/dns-proxy}"

# 3.1 未指定 --binary 时优先从源码现编（一次性消除"旧产物"这一类问题）
if [[ -z "$BINARY_ARG" ]] && command -v go >/dev/null 2>&1 \
   && [[ -f "$REPO_ROOT/proxy/main.go" ]]; then
  BUILD_REV="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  log "从源码编译代理（rev=$BUILD_REV，静态 linux/amd64）…"
  ( cd "$REPO_ROOT/proxy" && \
    GOPROXY="${GOPROXY:-https://goproxy.cn,direct}" GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags "-X main.buildRev=$BUILD_REV -X main.buildTime=$BUILD_TIME" \
      -o "$REPO_ROOT/bin/dns-proxy" . ) \
    || die "代理编译失败（检查 Go 工具链/GOPROXY；离线环境可加 --binary 指定已上传二进制）"
  log "编译完成：$REPO_ROOT/bin/dns-proxy"
elif [[ -z "$BINARY_ARG" ]]; then
  warn "未检测到 Go 工具链，改用已有产物：$BINARY（将做一致性校验）"
fi

[[ -x "$BINARY" ]] || die "代理二进制不存在：$BINARY
  请先在任意有 Go>=1.21 的机器上交叉编译并放到该路径：
    cd proxy && GOPROXY=https://goproxy.cn,direct GOOS=linux GOARCH=amd64 go build -o ../bin/dns-proxy .
  或用 --binary 指定已上传的二进制位置（如 /tmp/dns-proxy）"

# 3.2 格式校验：必须是 Linux ELF（防"在 Windows/macOS 上 make proxy 出的产物"被误装）
if [[ "$(head -c 4 "$BINARY" 2>/dev/null | od -An -tx1 | tr -d ' \n')" != "7f454c46" ]]; then
  die "拒绝安装：$BINARY 不是 Linux ELF 可执行文件（ELF 魔数不符）。
  常见原因：直接用 make proxy 在非 Linux 机器上编译（该目标产出宿主平台二进制）。
  请交叉编译：cd proxy && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ../bin/dns-proxy ."
fi

# 3.3 一致性校验 A：产物不得比源码旧（mtime 口径，不需要 go/git）
# 用 -print 而非 -printf：后者是 GNU 扩展，缺了会静默返回空 → 校验形同虚设
if [[ -d "$REPO_ROOT/proxy" ]]; then
  NEWER="$(find "$REPO_ROOT/proxy" -maxdepth 1 -name '*.go' -newer "$BINARY" 2>/dev/null | sort || true)"
  if [[ -n "$NEWER" ]]; then
    NEWER_SHOW="$(printf '%s\n' "$NEWER" | head -3 | while read -r f; do
      printf '      %s  %s\n' "$(date -r "$f" '+%Y-%m-%d %H:%M')" "$f"
    done)"
    msg="拒绝安装：$BINARY 比下列源码文件旧，说明它是源码更新前编译的旧产物：
$NEWER_SHOW
  → 这正是 2026-10-14「客户端 IP 长期为空」的事故成因。
  请重新编译后重试：cd proxy && go build -o ../bin/dns-proxy .
  （离线/无 Go 环境：在别处编译后加 --binary 传入；确需装旧产物：--allow-stale）"
    if [[ $ALLOW_STALE -eq 1 ]]; then
      warn "安装的是旧产物（源码比二进制新），因 --allow-stale 显式放行："
      echo "$NEWER_SHOW" >&2
    else
      die "$msg"
    fi
  fi
fi

# 3.4 一致性校验 B：版本戳 vs 仓库 HEAD（需二进制支持 -version，即本次改动之后编译的）
HEAD_REV="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || true)"
BIN_REV="$("$BINARY" -version 2>/dev/null | grep -oE 'rev=[0-9a-f]+' | cut -d= -f2 || true)"
if [[ -n "$HEAD_REV" && -n "$BIN_REV" && "$BIN_REV" != "unknown" ]]; then
  if [[ "$BIN_REV" != "$HEAD_REV" ]]; then
    if [[ $ALLOW_STALE -eq 1 ]]; then
      warn "版本戳不一致（二进制 rev=$BIN_REV / 仓库 HEAD=$HEAD_REV），因 --allow-stale 放行"
    else
      die "拒绝安装：二进制编译自 rev=$BIN_REV，而仓库 HEAD=$HEAD_REV —— 产物与源码脱钩。
  重新编译：cd proxy && go build -o ../bin/dns-proxy .
  确需安装该产物：--allow-stale"
    fi
  else
    log "版本戳校验通过：二进制与仓库 HEAD 一致（rev=$BIN_REV）"
  fi
elif [[ -n "$HEAD_REV" ]]; then
  # 拿不到产物版本戳：可能是本次加固之前编译的旧产物，也可能本机跑不动该架构
  # 的二进制。绝不能静默跳过——原事故正是"旧产物 + 无线索"。
  warn "产物无可解析的版本戳（$BIN_REV${BIN_REV:-<空>}）：无法与仓库 HEAD（$HEAD_REV）交叉验证，"
  warn "仅靠 mtime 校验兜底。建议重新编译以获得可自证版本的产物：cd proxy && go build -o ../bin/dns-proxy ."
fi

install -m 0755 "$BINARY" "$INSTALL_DIR/bin/dns-proxy"

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

# ---- 6 内核参数调优（幂等追加；句柄由 systemd LimitNOFILE 承担）-------------
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
  log "内核参数（收发缓冲/backlog）已就绪"
fi

# ---- 7 自检 ------------------------------------------------------------------
sleep 2
systemctl is-active --quiet proxy || { journalctl -u proxy -n 20 --no-pager; die "服务未正常运行，上方为最近日志"; }
log "自检通过：proxy 服务运行中"
if command -v ss >/dev/null 2>&1; then
  ss -lun | grep -q ":${LISTEN_PORT} " && log "自检通过：UDP $LISTEN_PORT 已监听" || warn "UDP $LISTEN_PORT 暂未监听（可能启动中，稍后 ss -lun 复查）"
fi

LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[[ -n "$LOCAL_IP" ]] || LOCAL_IP=$(ip -4 route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="src")print $(i+1)}' | head -1)

echo
log "机 A（代理）安装完成。后续两步："
echo "  1) 防火墙：仅放行各域控（DC）IP 访问本机 ${LISTEN_PORT}/UDP+TCP"
echo "  2) 域控转发器：每台 DC 的 DNS 转发器指向 ${LOCAL_IP:-本机IP}:${LISTEN_PORT}（先灰度 1 台）"
echo "     改配置：$CONFIG（含逐项注释说明，改后 systemctl restart proxy）"
