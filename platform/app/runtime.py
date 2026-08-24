"""运行时配置同步：system_config（DB） ↔ CONFIG（内存对象）。

- 启动时：DB 值覆盖 CONFIG 同名属性（Web 修改过的配置重启后仍生效）
- Web 修改时：set_config 同时写 DB + 内存，DNS 引擎每次查询直接读
  CONFIG 属性，立即热生效（无需重启服务）
"""

import logging

from config import CONFIG
from app.db import db_cursor

logger = logging.getLogger("platform.runtime")

# 类型转换规则：system_config 值均为字符串，落内存时需还原类型
_BOOL_KEYS = {"allow_log_enabled", "detection_enabled",
              "threatlist_auto_update"}
_INT_KEYS = {"alert_ttl", "log_retention_days", "api_timeout_ms",
             "threatlist_auto_interval_hours"}


def _apply(key: str, value: str) -> None:
    if not hasattr(CONFIG, key):
        return
    try:
        if key in _BOOL_KEYS:
            setattr(CONFIG, key, str(value).strip().lower() in ("1", "true", "yes", "on"))
        elif key in _INT_KEYS:
            setattr(CONFIG, key, int(value))
        else:
            setattr(CONFIG, key, str(value))
    except (ValueError, TypeError) as e:
        logger.warning("配置 %s=%s 应用失败: %s", key, value, e)


def sync_config_from_db() -> None:
    """启动时调用：把 system_config 全部键值同步进内存 CONFIG。"""
    with db_cursor() as cur:
        cur.execute("SELECT key, value FROM system_config")
        rows = cur.fetchall()
    for row in rows:
        _apply(row["key"], row["value"])
    logger.info("运行时配置已从数据库同步（%d 项）", len(rows))


def set_config(key: str, value: str) -> None:
    """写 system_config 并热更新内存 CONFIG。键不存在时插入。"""
    with db_cursor() as cur:
        cur.execute(
            """UPDATE system_config
               SET value=?, updated_at=datetime('now','localtime')
               WHERE key=?""",
            (str(value), key),
        )
        if cur.rowcount == 0:
            cur.execute(
                "INSERT INTO system_config (key, value) VALUES (?, ?)",
                (key, str(value)),
            )
    _apply(key, str(value))
