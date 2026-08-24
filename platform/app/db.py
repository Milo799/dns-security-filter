"""SQLite 连接与初始化。

单实例 + SQLite（PRD 技术选型）。所有 Web/DNS 模块共享一个连接，
SQLite 写并发低但本项目规模足够；必要时加简单锁即可。
"""

import os
import sqlite3
from contextlib import contextmanager

from config import CONFIG

_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")
_conn: sqlite3.Connection | None = None


def get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(CONFIG.database) or ".", exist_ok=True)
        _conn = sqlite3.connect(CONFIG.database, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL;")
        init_schema(_conn)
    return _conn


def init_schema(conn: sqlite3.Connection) -> None:
    with open(_SCHEMA_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    _migrate(conn)
    conn.commit()


def _migrate(conn: sqlite3.Connection) -> None:
    """轻量迁移：为旧库补齐新增列（SQLite 无 ADD COLUMN IF NOT EXISTS）。

    新增列必须与 schema.sql 保持一致（列名/类型/默认值），仅限追加列。
    """
    columns = {
        "adapter_type": "VARCHAR NOT NULL DEFAULT 'http'",
        "is_builtin": "BOOLEAN NOT NULL DEFAULT 0",
        "config": "TEXT DEFAULT ''",
        "description": "VARCHAR DEFAULT ''",
    }
    existing = {r["name"] for r in conn.execute(
        "PRAGMA table_info(threatintel_api)").fetchall()}
    for name, ddl in columns.items():
        if name not in existing:
            conn.execute(
                f"ALTER TABLE threatintel_api ADD COLUMN {name} {ddl}")


@contextmanager
def db_cursor():
    """事务化游标：正常提交、异常回滚。"""
    conn = get_conn()
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


# ---- 查询辅助（AI 开发指引：检测主流程可直接复用） ----

def get_enabled_list(list_type: str, target: str) -> list[str]:
    """读取启用的名单条目（detectors.match_list 用）。"""
    with db_cursor() as cur:
        cur.execute(
            "SELECT value FROM filter_list WHERE list_type=? AND target=? AND enabled=1",
            (list_type, target),
        )
        return [row["value"] for row in cur.fetchall()]


def get_system_config(key: str, default: str = "") -> str:
    with db_cursor() as cur:
        cur.execute("SELECT value FROM system_config WHERE key=?", (key,))
        row = cur.fetchone()
        return row["value"] if row else default
