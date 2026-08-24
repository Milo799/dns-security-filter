"""初始化：默认管理员 + 默认系统配置 + 内置开源情报源（首次启动时执行）。"""

import json
import logging

import bcrypt

from config import CONFIG
from app.db import get_conn

logger = logging.getLogger("platform.seed")

DEFAULT_SYSTEM_CONFIG = {
    "alert_ip": CONFIG.alert_ip,
    "alert_ttl": str(CONFIG.alert_ttl),
    "upstream_dns": CONFIG.upstream_dns,
    "fusion_strategy": CONFIG.fusion_strategy,
    "log_retention_days": str(CONFIG.log_retention_days),
    "allow_log_enabled": str(int(CONFIG.allow_log_enabled)),
    "detection_enabled": str(int(CONFIG.detection_enabled)),
}

# ---------------------------------------------------------------------------
# 内置开源情报源（免 API Key，开箱即用；默认停用，由管理员在界面启用）
#   adapter_type: http / dnsbl
#   dnsbl.config: {"zone": "...", "resolver": "..."} 可自定义
# ---------------------------------------------------------------------------
BUILTIN_THREATINTEL = [
    {
        "name": "spamhaus_zen",
        "adapter_type": "dnsbl",
        "base_url": "",
        "config": {"zone": "zen.spamhaus.org"},
        "description": "Spamhaus ZEN 综合 IP 信誉黑名单（SBL/XBL/PBL），免 Key",
    },
    {
        "name": "spamhaus_dbl",
        "adapter_type": "dnsbl",
        "base_url": "",
        "config": {"zone": "dbl.spamhaus.org"},
        "description": "Spamhaus DBL 域名黑名单（垃圾/钓鱼/恶意软件），免 Key",
    },
    {
        "name": "dronebl",
        "adapter_type": "dnsbl",
        "base_url": "",
        "config": {"zone": "dnsbl.dronebl.org"},
        "description": "DroneBL 僵尸网络/滥用 IP 黑名单（垃圾/暴力破解/恶意软件），免 Key",
    },
    {
        "name": "spfbl",
        "adapter_type": "dnsbl",
        "base_url": "",
        "config": {"zone": "dnsbl.spfbl.net"},
        "description": "SPFBL 综合垃圾/恶意域名与 IP 黑名单，免 Key",
    },
    {
        "name": "urlhaus",
        "adapter_type": "http",
        "base_url": "https://urlhaus-api.abuse.ch",
        "config": {"note": "开放 API 无需 Key；官方限速约 5 秒/次，建议默认停用，手动测试用"},
        "description": "URLhaus（abuse.ch）恶意 URL 分发库，支持域名与 IP",
    },
]


def init_builtin_threatintel(conn) -> None:
    """写入内置开源情报源（已存在不覆盖，保持管理员启停状态）。"""
    for item in BUILTIN_THREATINTEL:
        conn.execute(
            """INSERT OR IGNORE INTO threatintel_api
               (name, adapter_type, base_url, enabled, timeout_ms,
                is_builtin, config, description)
               VALUES (?, ?, ?, 0, ?, 1, ?, ?)""",
            (item["name"], item["adapter_type"], item["base_url"],
             CONFIG.api_timeout_ms,
             json.dumps(item["config"], ensure_ascii=False),
             item["description"]),
        )
    conn.commit()


def init_admin(conn) -> None:
    """不存在管理员则创建默认管理员（admin / admin_initial_password）。"""
    cur = conn.execute("SELECT COUNT(*) AS c FROM admin_user")
    if cur.fetchone()["c"] > 0:
        return
    password_hash = bcrypt.hashpw(
        CONFIG.admin_initial_password.encode(), bcrypt.gensalt()
    ).decode()
    conn.execute(
        "INSERT INTO admin_user (username, password_hash) VALUES (?, ?)",
        ("admin", password_hash),
    )
    conn.commit()
    logger.warning(
        "已创建默认管理员 admin，初始密码：%s（生产环境请立即修改！）",
        CONFIG.admin_initial_password,
    )


def init_system_config(conn) -> None:
    """缺失的配置键写入默认值（已存在的键不覆盖）。"""
    for key, value in DEFAULT_SYSTEM_CONFIG.items():
        conn.execute(
            "INSERT OR IGNORE INTO system_config (key, value) VALUES (?, ?)",
            (key, value),
        )
    conn.commit()


def init_all() -> None:
    conn = get_conn()
    init_admin(conn)
    init_system_config(conn)
    init_builtin_threatintel(conn)
    logger.info("平台初始化完成（数据库：%s）", CONFIG.database)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_all()
