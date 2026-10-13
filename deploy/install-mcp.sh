#!/usr/bin/env bash
# ============================================================================
# DNS 安全过滤 · MCP 服务安装脚本（AI Agent 操作接口）
# ============================================================================
# 用法（在仓库根目录执行，需 root）：
#   sudo ./deploy/install-mcp.sh
#
#   参数（均有默认值）：
#     --port          NUM    MCP 监听端口            默认 8090
#     --host          IP     绑定地址                默认 0.0.0.0（内网）
#     --token         STR    Bearer Token            默认自动生成
#     --api-base      URL    平台 Web 地址           默认 http://127.0.0.1:8080
#     --read-only            以只读模式安装（拒绝一切写操作）
#     --pip-proxy     URL    pip 代理（内网出站用）
#     --install-dir   DIR    安装目录                默认 /opt/dns-security-filter
#
# 脚本做 5 件事（幂等）：
#   1 前置检查（root / Linux / 平台已安装 / venv 存在）
#   2 安装 MCP SDK 到 platform venv（platform/requirements-mcp.txt）
#   3 生成 /etc/dnsfilter/mcp.env（600，含平台密码 + Bearer Token）
#   4 安装并启动 systemd 服务 dnsfilter-mcp
#   5 自检（端口监听 / 未授权被拒 / 带 Token 握手成功 / 工具数）
#
# 安全说明：
#   - MCP 服务不直连数据库，全部经平台 Web API（复用鉴权/校验/审计）；
#   - HTTP 传输强制 Bearer Token（未设置 token 时服务拒绝启动，不裸奔）；
#   - 写操作三重闸门：DNSF_MCP_ALLOW_WRITE → 调用方 confirm → 平台审计；
#   - 断网/离线不影响 DNS 解析：MCP 挂了只影响 Agent 操作，不影响检测。
# ============================================================================
set -euo pipefail

PORT=8090
HOST=0.0.0.0
TOKEN=""
API_BASE="http://127.0.0.1:8080"
ALLOW_WRITE=1
PIP_PROXY=""
INSTALL_DIR=/opt/dns-security-filter
ENV_FILE=/etc/dnsfilter/mcp.env

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --host) HOST="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --api-base) API_BASE="$2"; shift 2 ;;
    --read-only) ALLOW_WRITE=0; shift ;;
    --pip-proxy) PIP_PROXY="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "未知参数：$1（-h 看用法）"; exit 2 ;;
  esac
done

log() { echo -e "\033[1;36m[MCP]\033[0m $*"; }
die() { echo -e "\033[1;31m[错误]\033[0m $*" >&2; exit 1; }

# ── 1 前置检查 ──────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "请用 root 执行（sudo $0）"
[[ -f "$INSTALL_DIR/platform/mcp_server.py" ]] || \
  die "未找到 $INSTALL_DIR/platform/mcp_server.py —— 请确认平台已安装且代码已更新（git pull）"
[[ -x "$INSTALL_DIR/platform/venv/bin/python" ]] || \
  die "未找到平台 venv：$INSTALL_DIR/platform/venv（先跑 deploy/install-platform.sh）"
log "前置检查通过（平台：$INSTALL_DIR）"

# ── 2 安装 MCP SDK ─────────────────────────────────────────────────────────
PY="$INSTALL_DIR/platform/venv/bin/python"
PIP="$INSTALL_DIR/platform/venv/bin/pip"
PIP_ARGS=(-q)
[[ -n "$PIP_PROXY" ]] && PIP_ARGS+=(--proxy "$PIP_PROXY")
if "$PY" -c "import mcp" 2>/dev/null; then
  log "MCP SDK 已存在：$("$PY" -c 'import mcp,importlib.metadata as m;print(m.version("mcp"))')"
else
  log "安装 MCP SDK（platform/requirements-mcp.txt）…"
  "$PIP" install "${PIP_ARGS[@]}" -r "$INSTALL_DIR/platform/requirements-mcp.txt" || \
    die "MCP SDK 安装失败（内网请加 --pip-proxy http://<代理>:<端口>）"
  log "MCP SDK 安装完成"
fi

# ── 3 生成环境文件 ─────────────────────────────────────────────────────────
if [[ -z "$TOKEN" ]]; then
  TOKEN="$("$PY" - <<'PYEOF'
import secrets
print(secrets.token_urlsafe(32))
PYEOF
)"
  log "已生成随机 Bearer Token"
fi

# 平台密码：优先取已有环境文件，其次读 platform.yaml 的 admin_initial_password
API_PWD=""
if [[ -f "$ENV_FILE" ]]; then
  API_PWD="$(grep -E '^DNSF_API_PASSWORD=' "$ENV_FILE" | cut -d= -f2- || true)"
fi
if [[ -z "$API_PWD" && -f "$INSTALL_DIR/platform/platform.yaml" ]]; then
  API_PWD="$("$PY" - <<PYEOF
import yaml
with open("$INSTALL_DIR/platform/platform.yaml", encoding="utf-8") as f:
    cfg = yaml.safe_load(f) or {}
print(cfg.get("admin_initial_password") or "")
PYEOF
)"
fi
[[ -n "$API_PWD" ]] || die "拿不到平台管理员密码：请在 $ENV_FILE 里设置 DNSF_API_PASSWORD"

mkdir -p "$(dirname "$ENV_FILE")"
cat > "$ENV_FILE" <<EOF
# DNS 安全过滤 · MCP 服务环境（${ENV_FILE}）
# 本文件含平台凭据与 Bearer Token，务必保持 600 权限、不要提交到仓库。
DNSF_API_BASE=${API_BASE}
DNSF_API_USER=admin
DNSF_API_PASSWORD=${API_PWD}
DNSF_MCP_TRANSPORT=http
DNSF_MCP_HOST=${HOST}
DNSF_MCP_PORT=${PORT}
DNSF_MCP_TOKEN=${TOKEN}
DNSF_MCP_ALLOW_WRITE=${ALLOW_WRITE}
DNSF_MCP_AGENT=agent
DNSF_MCP_TIMEOUT=20
EOF
chmod 600 "$ENV_FILE"
chown root:root "$ENV_FILE" 2>/dev/null || true
log "环境文件已写入：$ENV_FILE（$( [[ $ALLOW_WRITE -eq 1 ]] && echo '读写' || echo '只读' )）"

# ── 4 安装 systemd 服务 ────────────────────────────────────────────────────
SRC_UNIT="$(dirname "$0")/dnsfilter-mcp.service"
[[ -f "$SRC_UNIT" ]] || die "缺少 unit 文件：$SRC_UNIT"
install -m 644 "$SRC_UNIT" /etc/systemd/system/dnsfilter-mcp.service

# ExecStart 的端口跟随 --port
if [[ "$PORT" != "8090" ]]; then
  sed -i "s|--port 8090|--port ${PORT}|" /etc/systemd/system/dnsfilter-mcp.service
fi
systemctl daemon-reload
systemctl enable dnsfilter-mcp >/dev/null 2>&1 || true
systemctl restart dnsfilter-mcp
sleep 3
log "服务状态：$(systemctl is-active dnsfilter-mcp)"

# ── 5 自检 ────────────────────────────────────────────────────────────────
echo
log "──── 自检 ────"
systemctl is-active --quiet dnsfilter-mcp && log "✔ 进程 active" || die "服务未启动：journalctl -u dnsfilter-mcp -n 30"

ss -tln 2>/dev/null | grep -q ":${PORT} " && log "✔ 端口 ${PORT} 监听中" || die "端口 ${PORT} 未监听"

CODE_NOAUTH="$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 \
  -X POST "http://127.0.0.1:${PORT}/mcp" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' || echo 000)"
if [[ "$CODE_NOAUTH" == "401" ]]; then
  log "✔ 未带 Token 被拒（HTTP 401）"
else
  log "⚠ 未带 Token 返回 HTTP ${CODE_NOAUTH}（期望 401，请检查 DNSF_MCP_TOKEN）"
fi

"$PY" - "$HOST" "$PORT" "$TOKEN" <<'PYEOF' && log "✔ MCP 握手与工具清单正常" || die "MCP 握手失败，见上方输出"
import asyncio, json, sys
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

host, port, token = sys.argv[1], sys.argv[2], sys.argv[3]
url = f"http://127.0.0.1:{port}/mcp"

async def main():
    async with streamablehttp_client(
            url, headers={"Authorization": "Bearer " + token}) as (r, w, _):
        async with ClientSession(r, w) as s:
            info = await s.initialize()
            tools = (await s.list_tools()).tools
            writes = [t.name for t in tools
                      if "confirm" in (t.input_schema or {}).get("properties", {})]
            print(f"   服务 {info.server_info.name} v{info.server_info.version}｜"
                  f"工具 {len(tools)} 个（写 {len(writes)}）")
asyncio.run(main())
PYEOF

echo
log "安装完成。常用命令："
echo "  systemctl status dnsfilter-mcp          # 服务状态"
echo "  journalctl -u dnsfilter-mcp -f          # 实时日志（含 MCP_WRITE 审计行）"
echo "  grep DNSF_MCP_TOKEN $ENV_FILE           # 取 Bearer Token"
echo
echo "  远端 Agent 接入（streamable-http）："
echo "    URL   : http://<本机IP>:${PORT}/mcp"
echo "    Header: Authorization: Bearer <上述 Token>"
echo
echo "  本机 Agent 接入（stdio，无需 Token）："
echo "    command: $PY"
echo "    args   : ['$INSTALL_DIR/platform/mcp_server.py']"
echo "    env    : DNSF_API_BASE=${API_BASE} DNSF_API_PASSWORD=<平台密码> DNSF_MCP_AGENT=<名字>"
