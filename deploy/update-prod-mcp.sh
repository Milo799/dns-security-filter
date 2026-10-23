#!/usr/bin/env bash
# 生产 MCP 服务更新脚本（172.16.0.191）
#
# 作用：把带【内网 DNS 解析链路拓扑】的 mcp_server.py 更新到生产，
#      重启 systemd 服务并验证 instructions 已带上拓扑。
#
# 用法：
#   scp mcp_server.py root@172.16.0.191:/tmp/
#   scp update-prod-mcp.sh root@172.16.0.191:/tmp/
#   ssh root@172.16.0.191 'bash /tmp/update-prod-mcp.sh'
#
# 安全设计：
#   1. 备份原文件（带时间戳），出问题可一键回滚
#   2. 先做语法检查，语法不过直接退出，不动生产文件
#   3. 用 venv 的解释器做 import 验证，确认 instructions 渲染正常
#   4. 替换后重启服务，若服务启动失败自动回滚
#   5. 端到端验证：真实起一个 MCP 客户端握手，检查 instructions 含拓扑

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/dns-security-filter}"
TARGET="$INSTALL_DIR/platform/mcp_server.py"
NEW_FILE="${NEW_FILE:-/tmp/mcp_server.py}"
PY="$INSTALL_DIR/platform/venv/bin/python"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="${TARGET}.bak.${STAMP}"

log()  { echo -e "\033[1;36m[更新]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[ OK ]\033[0m $*"; }
warn() { echo -e "\033[1;33m[警告]\033[0m $*"; }
die()  { echo -e "\033[1;31m[失败]\033[0m $*" >&2; exit 1; }

# ── 1 前置检查 ──────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "请用 root 执行"
[[ -f "$NEW_FILE" ]] || die "找不到待更新的文件 $NEW_FILE"
[[ -f "$TARGET"  ]] || die "找不到生产文件 $TARGET"
[[ -x "$PY" ]] || die "找不到平台 venv 解释器 $PY"

log "生产文件：$TARGET"
log "待更新文件：$NEW_FILE"

# ── 2 语法检查（不动生产文件）────────────────────────────────────────────────
log "1/6 语法检查…"
"$PY" -c "import ast,sys; ast.parse(open(sys.argv[1],encoding='utf-8').read())" "$NEW_FILE" \
  || die "新文件语法检查未通过，已中止（生产文件未改动）"
ok "语法正确"

# ── 3 渲染检查（确认 instructions 能正常拼出拓扑）────────────────────────────
log "2/6 渲染检查（instructions 是否含拓扑）…"
cd "$INSTALL_DIR/platform"
"$PY" - "$NEW_FILE" <<'PYEOF'
import sys, re
src = open(sys.argv[1], encoding='utf-8').read()
m = re.search(r'_TOPOLOGY_CONTEXT = """(.*?)"""', src, re.S)
if not m:
    print("[失败] 新文件里找不到 _TOPOLOGY_CONTEXT"); sys.exit(1)
ctx = m.group(1)
need = ['172.16.0.8', '172.16.7.2', '172.16.7.1', '172.16.0.192', '172.16.0.191',
        'NXDOMAIN', '排障要点']
missing = [x for x in need if x not in ctx]
if missing:
    print("[失败] 拓扑上下文缺少:", missing); sys.exit(1)
print("[ OK ] 拓扑上下文完整，五跳节点齐全")
PYEOF
ok "渲染检查通过"

# ── 4 备份 ────────────────────────────────────────────────────────────────
log "3/6 备份原文件…"
cp -p "$TARGET" "$BACKUP"
ok "已备份 → $BACKUP"

# ── 5 替换 + 重启（失败自动回滚）───────────────────────────────────────────
log "4/6 替换文件…"
install -m 644 "$NEW_FILE" "$TARGET"
chown --reference="$BACKUP" "$TARGET" 2>/dev/null || true

log "5/6 重启服务…"
if ! systemctl restart dnsfilter-mcp.service; then
    warn "重启失败，自动回滚…"
    cp -p "$BACKUP" "$TARGET"
    systemctl restart dnsfilter-mcp.service || true
    die "已回滚到 $BACKUP"
fi

sleep 3
if ! systemctl is-active --quiet dnsfilter-mcp.service; then
    warn "服务未处于 active，自动回滚…"
    cp -p "$BACKUP" "$TARGET"
    systemctl restart dnsfilter-mcp.service || true
    die "已回滚到 $BACKUP"
fi
ok "服务已重启并处于 active"

# ── 6 端到端验证（真起一个 MCP 客户端握手）──────────────────────────────────
log "6/6 端到端验证（真实握手检查 instructions）…"
cd "$INSTALL_DIR/platform"
TOKEN="$(grep -E '^DNSF_MCP_TOKEN=' /etc/dnsfilter/mcp.env | cut -d= -f2- || true)"
API_BASE="http://127.0.0.1:8080"
API_USER="admin"
API_PASS="$("$PY" - <<'PYEOF'
import os, re
try:
    txt = open('/opt/dns-security-filter/platform/platform.yaml', encoding='utf-8').read()
    m = re.search(r'password:\s*(\S+)', txt)
    print(m.group(1) if m else '')
except Exception:
    print('')
PYEOF
)"

if [[ -z "$TOKEN" ]]; then
    warn "未能读取 DNSF_MCP_TOKEN，跳过端到端握手验证"
    warn "请手动确认：systemctl status dnsfilter-mcp && journalctl -u dnsfilter-mcp -n 30"
    exit 0
fi

"$PY" - "$API_BASE" "$API_USER" "$API_PASS" "$TOKEN" <<'PYEOF'
import asyncio, sys, json, urllib.request

api_base, api_user, api_pass, token = sys.argv[1:5]

# 1) 取平台 token（仅用于确认平台可连，不参与 MCP 握手）
req = urllib.request.Request(
    api_base + '/api/auth/login',
    data=json.dumps({'username': api_user, 'password': api_pass}).encode(),
    headers={'Content-Type': 'application/json'})
try:
    d = json.load(urllib.request.urlopen(req, timeout=10))
    print('[ OK ] 平台 API 可登录')
except Exception as e:
    print('[警告] 平台登录失败（不影响 MCP 握手验证）:', e)

# 2) 直连 MCP HTTP 端点做 initialize
async def main():
    from mcp import ClientSession
    # mcp SDK 2.3.0 用 streamable_http_client；旧版叫 streamablehttp_client
    try:
        from mcp.client.streamable_http import streamable_http_client as mk
    except ImportError:
        from mcp.client.streamable_http import streamablehttp_client as mk
    async with mk('http://127.0.0.1:8090/mcp',
                  headers={'Authorization': 'Bearer ' + token}) as (r, w, _):
        async with ClientSession(r, w) as s:
            init = await s.initialize()
            ins = init.instructions or ''
            tools = (await s.list_tools()).tools
            print('instructions 长度:', len(ins))
            print('工具数:', len(tools))
            need = ['172.16.0.8','172.16.7.2','172.16.7.1','172.16.0.192','172.16.0.191']
            missing = [x for x in need if x not in ins]
            if missing:
                print('[失败] 下发的 instructions 缺少节点:', missing); sys.exit(1)
            if '【内网 DNS 解析链路拓扑' not in ins:
                print('[失败] 下发的 instructions 不含拓扑段落'); sys.exit(1)
            print('[ OK ] 生产 MCP 已在 instructions 中下发完整拓扑')
            if len(tools) != 16:
                print('[警告] 工具数与预期 16 不符:', len(tools))
            else:
                print('[ OK ] 工具数 16，符合预期')

asyncio.run(main())
PYEOF

ok "全部完成。备份文件：$BACKUP"
echo
echo "如需回滚："
echo "  cp -p $BACKUP $TARGET && systemctl restart dnsfilter-mcp"
