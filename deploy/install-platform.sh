#!/usr/bin/env bash
# ============================================================================
# DNS 安全过滤 · 机 B（检测平台）一键安装脚本
# ============================================================================
# 用法（在仓库根目录执行）：
#   sudo ./deploy/install-platform.sh --upstream-dns 223.5.5.5
#
#   完整参数（均有默认值，见下）：
#     --dns-port       NUM   平台 DNS 监听端口（代理转发到这） 默认 15353
#     --web-port       NUM   Web 管理端口                      默认 8080
#     --upstream-dns   IP    放行域名的公网递归 DNS            默认 223.5.5.5
#     --alert-ip       IP    拦截应答的告警引导页 IP           默认 127.0.0.1
#     --memory-max     SIZE  systemd MemoryMax（防缓存打爆）   默认 24G
#     --pip-mirror     URL   pip 国内镜像                      默认清华源
#     --install-dir    DIR   安装目录                          默认 /opt/dns-security-filter
#     --skip-tuning          跳过 sysctl/limits 内核参数调优
#
# 脚本做 10 件事（全部幂等，可重复执行）：
#   1 环境检测（root / Linux / Python>=3.10 / 内存预警）
#   2 创建 dnsfilter 系统用户与目录
#   3 复制平台代码 + Web 前端 + tools 工具脚本
#   4 venv + pip 依赖安装（国内镜像）
#   5 自动生成 jwt_secret 与管理员初始密码，从 platform.example.yaml
#     生成带全量注释的 platform.yaml（已存在则保留）
#   6 安装并启动 systemd 服务 platform-dns + platform-web
#   7 内核参数调优（DNS 高并发收发缓冲）
#   8 文件句柄上限
#   9 数据库每日备份（dnsfilter-backup.timer，02:30 热备 + 保留 14 份）
#  10 自检（服务状态 / 端口监听 / 健康接口）
# ============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ---- 默认值 ----------------------------------------------------------------
DNS_PORT=15353
WEB_PORT=8080
UPSTREAM_DNS="223.5.5.5"
ALERT_IP="127.0.0.1"
MEMORY_MAX="24G"
PIP_MIRROR="https://pypi.tuna.tsinghua.edu.cn/simple"
INSTALL_DIR="/opt/dns-security-filter"
SKIP_TUNING=0
APP_USER="dnsfilter"

# ---- 参数解析 --------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dns-port)       DNS_PORT="$2"; shift 2 ;;
    --web-port)       WEB_PORT="$2"; shift 2 ;;
    --upstream-dns)   UPSTREAM_DNS="$2"; shift 2 ;;
    --alert-ip)       ALERT_IP="$2"; shift 2 ;;
    --memory-max)     MEMORY_MAX="$2"; shift 2 ;;
    --pip-mirror)     PIP_MIRROR="$2"; shift 2 ;;
    --install-dir)    INSTALL_DIR="$2"; shift 2 ;;
    --skip-tuning)    SKIP_TUNING=1; shift ;;
    -h|--help)        grep '^#' "$0" | sed 's/^# \{0,2\}//'; exit 0 ;;
    *) echo "未知参数: $1（--help 查看用法）" >&2; exit 1 ;;
  esac
done

log()  { echo -e "\033[1;32m==>\033[0m $*"; }
warn() { echo -e "\033[1;33m[警告]\033[0m $*" >&2; }
die()  { echo -e "\033[1;31m[错误]\033[0m $*" >&2; exit 1; }

# ---- 1 环境检测 ------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "请用 root 运行：sudo $0"
[[ "$(uname -s)" == "Linux" ]] || die "本脚本仅支持 Linux（当前 $(uname -s)）"

PY_OK=0
for cand in python3 python3.12 python3.11 python3.10 /usr/bin/python3; do
  if command -v "$cand" >/dev/null 2>&1; then
    if "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
      PYTHON_BIN="$cand"; PY_OK=1; break
    fi
  fi
done
[[ $PY_OK -eq 1 ]] || die "未找到 Python >=3.10（平台运行必需）。请先安装：
  AlmaLinux/RHEL 8: dnf install python3.12 python3.12-pip python3.12-setuptools（需系统>=8.10）
                    或 python3.11 python3.11-pip（>=8.7）
  Debian/Ubuntu:   apt install python3 python3-venv"
# RHEL 系坑：只装 python3.12 不装 python3.12-pip 时，venv 的 ensurepip 环节会失败——
# 提前探测 pip 可用性，把报错拦在最前面（而不是走到 venv 创建才炸）
if [[ $PY_OK -eq 1 ]] && ! "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; then
  warn "检测到 $PYTHON_BIN 缺少 pip 模块（RHEL 系单独拆包）——venv 创建将失败"
  warn "先补装再重跑本脚本：dnf install -y ${PYTHON_BIN}-pip ${PYTHON_BIN}-setuptools"
fi
log "Python：$("$PYTHON_BIN" -V 2>&1)"
log "内存：$(free -h | awk '/^Mem:/{print $2}')；磁盘可用：$(df -h / | awk 'NR==2{print $4}')"

# 内存太低提前预警（不阻断——允许小规模部署压测）
MEM_MB=$(free -m | awk '/^Mem:/{print $2}')
if [[ "${MEM_MB:-0}" -lt 8000 ]]; then
  warn "内存 ${MEM_MB}MB < 建议 16G（离线大名单 + 结论缓存主要吃内存）。"
  warn "小内存场景：用 hagezi_mini 名单 + domain_cache_size 降到 200000，并把 --memory-max 调小。"
fi

# ---- 2 用户与目录 -----------------------------------------------------------
id "$APP_USER" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$APP_USER"
mkdir -p "$INSTALL_DIR"
log "安装目录：$INSTALL_DIR（运行用户：$APP_USER）"

# ---- 3 代码落位（tar 保持兼容性；保留 venv/data/platform.yaml/pyc 缓存）----
if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete --exclude 'venv' --exclude 'data' --exclude 'platform.yaml' --exclude '__pycache__' \
        "$REPO_ROOT/platform/" "$INSTALL_DIR/platform/"
  rsync -a --delete "$REPO_ROOT/web/" "$INSTALL_DIR/web/"
  rsync -a "$REPO_ROOT/tools/" "$INSTALL_DIR/tools/"
else
  (cd "$REPO_ROOT" && tar cf - --exclude='platform/venv' --exclude='platform/data' \
      --exclude='platform/platform.yaml' --exclude='platform/__pycache__' \
      --exclude='*/__pycache__' platform web tools) | (cd "$INSTALL_DIR" && tar xf -)
fi
mkdir -p "$INSTALL_DIR/platform/data"
chmod +x "$INSTALL_DIR/tools/"*.sh 2>/dev/null || true

# ---- 4 venv + 依赖 ----------------------------------------------------------
if [[ ! -x "$INSTALL_DIR/platform/venv/bin/python" ]]; then
  if ! "$PYTHON_BIN" -m venv "$INSTALL_DIR/platform/venv" 2>/tmp/dnsf-venv-err.log; then
    # ensurepip 失败的兜底：--without-pip 建裸 venv，再用系统 pip 注入引导（get-pip 或 pip install）
    warn "标准 venv 创建失败（常见原因：RHEL 系未装 ${PYTHON_BIN}-pip，ensurepip 报错）——尝试 --without-pip 兜底方案"
    rm -rf "$INSTALL_DIR/platform/venv"
    if "$PYTHON_BIN" -m venv --without-pip "$INSTALL_DIR/platform/venv" 2>>/tmp/dnsf-venv-err.log; then
      VENV_PY="$INSTALL_DIR/platform/venv/bin/python"
      # 注入路径 1：系统有 pip 模块 → 直接给它装进 venv
      if "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; then
        "$PYTHON_BIN" -m pip install -q --prefix "$INSTALL_DIR/platform/venv" pip -i "$PIP_MIRROR" 2>>/tmp/dnsf-venv-err.log || true
      fi
      # 注入路径 2（更可靠）：下载 get-pip.py 引导安装
      if [[ ! -x "$INSTALL_DIR/platform/venv/bin/pip" ]]; then
        if curl -sf -m 30 "https://bootstrap.pypa.io/get-pip.py" -o /tmp/dnsf-get-pip.py 2>>/tmp/dnsf-venv-err.log \
           || curl -sf -m 30 "https://mirrors.aliyun.com/pypi/get-pip.py" -o /tmp/dnsf-get-pip.py 2>>/tmp/dnsf-venv-err.log; then
          "$VENV_PY" /tmp/dnsf-get-pip.py -q -i "$PIP_MIRROR" 2>>/tmp/dnsf-venv-err.log || true
          rm -f /tmp/dnsf-get-pip.py
        fi
      fi
      # 注入路径 3（终极兜底）：系统 pip wheel 离线拷入（setuptools 同带）
      if [[ ! -x "$INSTALL_DIR/platform/venv/bin/pip" ]] && command -v pip3.12 >/dev/null 2>&1; then
        SYS_SITE=$("$PYTHON_BIN" -c "import sysconfig; print(sysconfig.get_paths()['purelib'])")
        VENV_SITE=$("$VENV_PY" -c "import sysconfig; print(sysconfig.get_paths()['purelib'])")
        cp -r "$SYS_SITE/pip"* "$SYS_SITE/setuptools"* "$VENV_SITE/" 2>>/tmp/dnsf-venv-err.log || true
      fi
      if [[ ! -x "$INSTALL_DIR/platform/venv/bin/pip" ]]; then
        rm -rf "$INSTALL_DIR/platform/venv"
        die "venv 兜底方案仍无法获得 pip。请补装后重跑本脚本：
  AlmaLinux/RHEL 8: dnf install -y ${PYTHON_BIN}-pip ${PYTHON_BIN}-setuptools
  Debian/Ubuntu:    apt install python3-venv
  失败详情见 /tmp/dnsf-venv-err.log（补装后脚本幂等可重跑）"
      fi
      log "venv 兜底方案成功（--without-pip + pip 注入）"
    else
      rm -rf "$INSTALL_DIR/platform/venv"
      die "创建 venv 失败（非 ensurepip 原因）。失败详情见 /tmp/dnsf-venv-err.log：
  AlmaLinux/RHEL 8: dnf install -y ${PYTHON_BIN}-pip ${PYTHON_BIN}-setuptools
  Debian/Ubuntu:    apt install python3-venv"
    fi
  fi
fi
log "安装 Python 依赖（镜像 $PIP_MIRROR，首次约 1~3 分钟）…"
"$INSTALL_DIR/platform/venv/bin/pip" install -q --upgrade pip -i "$PIP_MIRROR" >/dev/null 2>&1 || true
"$INSTALL_DIR/platform/venv/bin/pip" install -q -r "$INSTALL_DIR/platform/requirements.txt" -i "$PIP_MIRROR"
log "依赖安装完成（venv：$INSTALL_DIR/platform/venv）"

# ---- 5 配置生成（自动生成密钥；替换键值、保留全量注释；已存在则保留）--------
CONFIG="$INSTALL_DIR/platform/platform.yaml"
GENERATED_CREDS=0
if [[ -f "$CONFIG" ]]; then
  warn "配置已存在，保留不覆盖：$CONFIG（如需重新生成请先备份删除）"
else
  JWT_SECRET="$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  ADMIN_PASS="dfs-$(head -c 9 /dev/urandom | base64 2>/dev/null | tr -d '/+=' | tr 'A-Z' 'a-z' | head -c 9)"
  # 注意 sed 地址范围：dns: 段与 web: 段各有一个 listen_port，必须分段替换
  sed -E \
    -e "/^dns:/,/^[a-z_]+:/{s|^(  listen_port:)[[:space:]]*[0-9]+|\1 $DNS_PORT|}" \
    -e "/^web:/,/^[a-z_]+:/{s|^(  listen_port:)[[:space:]]*[0-9]+|\1 $WEB_PORT|}" \
    -e "s|^(upstream_dns:)[[:space:]]*[^# ]+|\1 $UPSTREAM_DNS|" \
    -e "s|^(alert_ip:)[[:space:]]*[^# ]+|\1 $ALERT_IP|" \
    -e "s|^(  jwt_secret:)[[:space:]]*[^# ]+|\1 $JWT_SECRET|" \
    -e "s|^(admin_initial_password:)[[:space:]]*[^# ]+|\1 $ADMIN_PASS|" \
    "$REPO_ROOT/platform/platform.example.yaml" > "$CONFIG"
  chmod 0640 "$CONFIG"
  GENERATED_CREDS=1
  log "已生成配置 $CONFIG（dns.port=$DNS_PORT web.port=$WEB_PORT upstream_dns=$UPSTREAM_DNS alert_ip=$ALERT_IP）"
  log "已自动生成随机 jwt_secret（32 字节 hex）与 12 位管理员初始密码"
fi

# ---- 6 systemd 服务 --------------------------------------------------------
for unit in platform-dns platform-web; do
  sed -E -e "s|/opt/dns-security-filter|$INSTALL_DIR|g" \
         -e "s|MemoryMax=24G|MemoryMax=$MEMORY_MAX|" \
      "$REPO_ROOT/deploy/$unit.service" > "/etc/systemd/system/$unit.service"
done
systemctl daemon-reload
systemctl enable platform-dns platform-web >/dev/null 2>&1
systemctl restart platform-dns
sleep 3
systemctl restart platform-web
log "服务 platform-dns + platform-web 已安装并启动（开机自启）"

# ---- 7/8 内核参数与句柄上限（幂等追加）-------------------------------------
if [[ $SKIP_TUNING -eq 0 ]]; then
  touch /etc/sysctl.d/99-dnsfilter.conf
  for kv in "net.core.rmem_max=16777216" "net.core.wmem_max=16777216" "net.core.netdev_max_backlog=10000"; do
    key="${kv%%=*}"; want="${kv#*=}"
    cur=$(sysctl -n "$key" 2>/dev/null || echo 0)
    [[ "${cur:-0}" -lt "$want" ]] && echo "$kv" >> /etc/sysctl.d/99-dnsfilter.conf
  done
  tac /etc/sysctl.d/99-dnsfilter.conf | awk '!seen[$1]++' | tac > /etc/sysctl.d/99-dnsfilter.conf.tmp && \
    mv /etc/sysctl.d/99-dnsfilter.conf.tmp /etc/sysctl.d/99-dnsfilter.conf
  sysctl --system >/dev/null 2>&1 || true
  if ! grep -q "^${APP_USER} soft nofile" /etc/security/limits.conf 2>/dev/null; then
    echo "${APP_USER} soft nofile 65536" >> /etc/security/limits.conf
    echo "${APP_USER} hard nofile 65536" >> /etc/security/limits.conf
  fi
  log "内核参数（收发缓冲/backlog）与句柄上限已就绪"
fi

# ---- 9 数据库每日备份（P1-3：.backup 热备 + 保留份数轮转）--------------------
BACKUP_DIR="/var/backups/dnsfilter"
mkdir -p "$BACKUP_DIR"
chown "$APP_USER:$APP_USER" "$BACKUP_DIR"
chmod 0750 "$BACKUP_DIR"
for unit in dnsfilter-backup; do
  sed -e "s|/opt/dns-security-filter|$INSTALL_DIR|g" \
      "$REPO_ROOT/deploy/$unit.service" > "/etc/systemd/system/$unit.service"
done
cp "$REPO_ROOT/deploy/dnsfilter-backup.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable dnsfilter-backup.timer >/dev/null 2>&1
systemctl start dnsfilter-backup.timer
log "数据库每日备份已启用（02:30，保留 14 份，目录 $BACKUP_DIR）"
command -v sqlite3 >/dev/null 2>&1 || \
  warn "未安装 sqlite3 CLI，备份将降级 cp 拷贝（建议安装：AlmaLinux/RHEL 8 用 dnf install sqlite；Debian/Ubuntu 用 apt install sqlite3）"

# ---- 10 自检 ----------------------------------------------------------------
sleep 2
for unit in platform-dns platform-web; do
  systemctl is-active --quiet "$unit" || { journalctl -u "$unit" -n 20 --no-pager; die "$unit 未正常运行，上方为最近日志"; }
done
log "自检通过：platform-dns / platform-web 服务运行中"
if command -v ss >/dev/null 2>&1; then
  ss -lun | grep -q ":${DNS_PORT} "  && log "自检通过：DNS UDP $DNS_PORT 已监听"  || warn "DNS UDP $DNS_PORT 暂未监听（稍后 ss -lun 复查）"
  ss -ltn | grep -q ":${WEB_PORT} "  && log "自检通过：Web TCP $WEB_PORT 已监听"  || warn "Web TCP $WEB_PORT 暂未监听（稍后 ss -ltn 复查）"
fi
HEALTH=$(curl -sf -m 5 "http://127.0.0.1:${WEB_PORT}/api/health" 2>/dev/null || true)
[[ -n "$HEALTH" ]] && log "自检通过：健康接口应答 $HEALTH" || warn "健康接口暂无应答（服务可能仍在预热，稍后浏览器访问确认）"

chown -R "$APP_USER:$APP_USER" "$INSTALL_DIR"

# ---- 收尾输出 ---------------------------------------------------------------
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[[ -n "$LOCAL_IP" ]] || LOCAL_IP=$(ip -4 route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="src")print $(i+1)}' | head -1)

echo
log "机 B（检测平台）安装完成。后续四步："
echo "  1) 防火墙：DNS ${DNS_PORT}/UDP+TCP 仅放行机 A（代理）IP；Web ${WEB_PORT}/TCP 仅放行运维网段"
if [[ $GENERATED_CREDS -eq 1 ]]; then
  echo "  2) 管理员初始密码：$ADMIN_PASS  ← 首登 http://${LOCAL_IP:-本机IP}:${WEB_PORT} 后立即在 Web 修改"
fi
echo "  3) 导入离线大名单：威胁情报→离线情报源（hagezi_mini 起步；首导约 1~2 分钟）"
echo "  4) 代理机执行：sudo ./deploy/install-proxy.sh --upstream ${LOCAL_IP:-本机IP} --upstream-port $DNS_PORT"
echo "     改配置：$CONFIG（含逐项注释说明，dns/web/database 改后 systemctl restart platform-dns platform-web）"
