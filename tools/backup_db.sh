#!/usr/bin/env bash
# ============================================================================
# DNS 安全过滤 · platform.db 每日热备份脚本（P1-3）
# ============================================================================
# 用法（通常由 systemd timer 每日调起，也可手工执行）：
#   tools/backup_db.sh [数据库路径] [备份目录]
#
#   参数均可省略：
#     数据库路径  默认 /opt/dns-security-filter/platform/data/platform.db
#     备份目录    默认 /var/backups/dnsfilter
#
# 脚本做 4 件事：
#   1 sqlite3 ".backup" 在线热备（WAL 安全，不锁检测链路写入）
#   2 备份文件命名 platform-YYYYmmdd-HHMMSS.db，并压缩为 .gz
#   3 按保留份数（默认 14 份）轮转删除最旧备份
#   4 输出结果（供 journalctl 审计）；失败非零退出（触发 timer 告警语义）
#
# 依赖：sqlite3 CLI（AlmaLinux/RHEL 8: dnf install sqlite；Debian/Ubuntu: apt install sqlite3）。
# 无 sqlite3 CLI 时降级 cp（仅适合低峰窗口，会有短暂不一致风险），
# 脚本会明确打印降级提示。
# ============================================================================
set -euo pipefail

DB_PATH="${1:-/opt/dns-security-filter/platform/data/platform.db}"
BACKUP_DIR="${2:-/var/backups/dnsfilter}"
KEEP_COUNT="${BACKUP_KEEP:-14}"          # 保留份数（环境变量可覆盖）

log()  { echo "[backup] $*"; }
die()  { echo "[backup][错误] $*" >&2; exit 1; }

[[ -f "$DB_PATH" ]] || die "数据库不存在：$DB_PATH"

mkdir -p "$BACKUP_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
TARGET="$BACKUP_DIR/platform-$STAMP.db"

# ---- 1 在线热备（.backup 走 SQLite backup API，与写入并发安全） ----
if command -v sqlite3 >/dev/null 2>&1; then
    if ! sqlite3 "$DB_PATH" ".backup '$TARGET'"; then
        die "sqlite3 .backup 失败（检查磁盘空间与权限）"
    fi
else
    # 降级：直接拷贝（低峰窗口可接受；WAL 模式下拷主文件可能缺尾部事务）
    log "警告：未安装 sqlite3 CLI，降级为 cp 拷贝（建议 apt/yum 安装 sqlite3）"
    cp "$DB_PATH" "$TARGET"
fi

# ---- 2 压缩（SQLite 库内大量可压缩文本，通常 3~10 倍） ----
gzip -f "$TARGET"
TARGET="$TARGET.gz"

# ---- 3 保留份数轮转（按文件名时间戳排序，删最旧） ----
cd "$BACKUP_DIR"
TOTAL=$(ls -1 platform-*.db.gz 2>/dev/null | wc -l || echo 0)
if [[ "$TOTAL" -gt "$KEEP_COUNT" ]]; then
    REMOVE=$((TOTAL - KEEP_COUNT))
    ls -1 platform-*.db.gz | sort | head -n "$REMOVE" | while read -r f; do
        rm -f -- "$f"
        log "轮转删除旧备份：$f"
    done
fi

SIZE_H=$(du -h "$TARGET" | cut -f1)
log "备份完成：$TARGET（$SIZE_H，共保留 $TOTAL 份上限 $KEEP_COUNT）"
