#!/usr/bin/env bash
# 生产 git 仓库离线同步（git bundle 法）
#
# 背景：生产机访问不了 GitHub（出口代理 CONNECT 能建隧道但转发不出去，
#      且生产无 credential helper），git fetch 会一直挂起。
#      故改用 git bundle 离线同步。
#
# 用法：
#   # 1) 在能访问 GitHub 的开发机
#   git bundle create /tmp/dnsf-sync.bundle main
#   git bundle verify /tmp/dnsf-sync.bundle
#   scp /tmp/dnsf-sync.bundle root@172.16.0.191:/tmp/
#
#   # 2) 在生产机
#   bash deploy/sync-prod-git.sh /tmp/dnsf-sync.bundle
#
# 安全设计：
#   1. 同步前 stash 工作区改动（可回滚），不丢任何东西
#   2. 先验证可快进（--is-ancestor），非快进直接中止
#   3. 设置 core.autocrlf=input 消除行尾符造成的"假冲突"
#   4. tools/backup_db.sh 的 755 权限位必须保留（被备份定时器引用），
#      同步后强制恢复并校验
#   5. 修 origin/main 引用（生产 fetch 不到 GitHub，需手动指过去）
#   6. 同步后校验：HEAD == origin/main == 工作区 blob

set -euo pipefail

BUNDLE="${1:-/tmp/dnsf-sync.bundle}"
REPO="${REPO:-/opt/dns-security-filter}"
STAMP="$(date +%Y%m%d-%H%M%S)"

log()  { echo -e "\033[1;36m[同步]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[ OK ]\033[0m $*"; }
warn() { echo -e "\033[1;33m[警告]\033[0m $*"; }
die()  { echo -e "\033[1;31m[失败]\033[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "请用 root 执行"
[[ -f "$BUNDLE" ]] || die "找不到 bundle $BUNDLE"
[[ -d "$REPO/.git" ]] || die "$REPO 不是 git 仓库"

cd "$REPO"

log "仓库：$REPO"
log "bundle：$BUNDLE"
log "同步前 HEAD：$(git rev-parse --short HEAD)"

# ── 1 消除行尾符造成的假冲突 ───────────────────────────────────────────────
# 生产 core.autocrlf 未设置（false），开发机是 true → 同一份代码 blob hash
# 不同 → merge 会报 "local changes would be overwritten"，
# 实际只是 CRLF vs LF。设为 input（入库转 LF，工作区保持原样）是 Linux 正确做法。
log "1/6 设置 core.autocrlf=input…"
git config core.autocrlf input
git config core.safecrlf false
ok "已设置"

# ── 2 保护工作区 ──────────────────────────────────────────────────────────
STASHED=""
if ! git diff --quiet; then
    log "2/6 工作区有改动，先 stash…"
    git stash push -m "sync-${STAMP}: pre-fast-forward worktree" >/dev/null
    STASHED="yes"
    ok "已 stash（可用 git stash list 查看/回滚）"
else
    log "2/6 工作区干净，无需 stash"
fi

# ── 3 从 bundle 获取并验证可快进 ───────────────────────────────────────────
log "3/6 从 bundle 获取提交…"
git fetch "$BUNDLE" 'refs/heads/main:refs/remotes/bundle/main' 2>&1 | tail -2
TARGET="$(git rev-parse refs/remotes/bundle/main)"
ok "bundle/main = ${TARGET:0:7}"

if ! git merge-base --is-ancestor HEAD refs/remotes/bundle/main; then
    warn "非快进关系（生产有本地提交），已中止。工作区改动仍安全保留。"
    die "需要人工处理：git log --oneline HEAD..refs/remotes/bundle/main"
fi
ok "可快进（fast-forward）"

# ── 4 快进 ────────────────────────────────────────────────────────────────
log "4/6 快进 main…"
git merge --ff-only refs/remotes/bundle/main 2>&1 | tail -3
ok "已快进到 $(git rev-parse --short HEAD)"

# ── 5 修 origin/main 引用 + 恢复权限位 ─────────────────────────────────────
log "5/6 修 origin/main 引用…"
git update-ref refs/remotes/origin/main refs/remotes/bundle/main
ok "origin/main → $(git rev-parse --short origin/main)"

log "     恢复 backup_db.sh 可执行位…"
# 仓库里是 644，生产必须是 755——dnsfilter-backup.service 每天 02:30 引用它
chmod 755 tools/backup_db.sh 2>/dev/null || warn "tools/backup_db.sh 不存在，跳过"
MODE="$(stat -c '%a' tools/backup_db.sh 2>/dev/null || echo '?')"
[[ "$MODE" == "755" ]] && ok "backup_db.sh mode=755（备份定时器正常）" \
                       || warn "backup_db.sh mode=$MODE（应为 755）"

# ── 6 校验三方一致 ────────────────────────────────────────────────────────
log "6/6 校验一致性…"
H="$(git rev-parse HEAD)"
O="$(git rev-parse origin/main)"
W="$(git hash-object platform/mcp_server.py)"
R="$(git rev-parse HEAD:platform/mcp_server.py)"

[[ "$H" == "$O" ]] && ok "HEAD == origin/main == ${H:0:7}" \
                   || die "HEAD($H) != origin/main($O)"
[[ "$W" == "$R" ]] && ok "工作区 blob == 仓库 blob（mcp_server.py 完全一致）" \
                   || warn "工作区($W) != 仓库($R) —— 可能有行尾差异"

echo
log "同步完成。当前状态："
git status -sb | head -6
echo
if [[ -n "$STASHED" ]]; then
    echo "旧版本（同步前工作区）保留在 stash，可用以下命令查看/回滚："
    echo "  git stash list"
    echo "  git stash show -p stash@{0}"
fi
echo "如需回滚整个同步："
echo "  git reset --hard ${H:0:7}"
echo "  git update-ref refs/remotes/origin/main <同步前的 commit>"
