"""初始化：默认管理员 + 默认系统配置（首次启动时执行）。"""

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
    logger.info("平台初始化完成（数据库：%s）", CONFIG.database)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_all()
