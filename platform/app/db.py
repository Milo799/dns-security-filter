"""SQLite 连接与初始化。

单实例 + SQLite（PRD 技术选型）。连接按**线程隔离**（threading.local）：
- 每个线程持有独立连接，互不共享——避免多线程（后台导入/自动更新/
  Web 请求/检测主流程）在同一连接上交叉开事务导致的
  "cannot start a transaction within a transaction" / API misuse 报错；
- 同一线程内的 db_cursor() 事务语义不变（正常提交、异常回滚）；
- WAL 模式 + busy_timeout 30s：跨连接并发写时自动等待而非立刻报错。
"""

import os
import sqlite3
import threading
from contextlib import contextmanager

from config import CONFIG

_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")
_local = threading.local()
_init_lock = threading.Lock()   # 首次建表/迁移的跨线程互斥


def get_conn() -> sqlite3.Connection:
    """当前线程的 SQLite 连接（首次访问时创建并初始化）。"""
    conn = getattr(_local, "conn", None)
    if conn is not None:
        return conn
    with _init_lock:
        conn = getattr(_local, "conn", None)   # double-check
        if conn is not None:
            return conn
        os.makedirs(os.path.dirname(CONFIG.database) or ".", exist_ok=True)
        conn = sqlite3.connect(CONFIG.database, check_same_thread=False,
                               timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=30000;")
        init_schema(conn)
        _local.conn = conn
    return conn


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

    # 迭代 31：认证安全批次（admin_user 新增两列，存量库自动补齐）
    admin_cols = {
        "must_change": "BOOLEAN NOT NULL DEFAULT 0",
        "password_changed_at": "DATETIME",
    }
    admin_existing = {r["name"] for r in conn.execute(
        "PRAGMA table_info(admin_user)").fetchall()}
    for name, ddl in admin_cols.items():
        if name not in admin_existing:
            conn.execute(f"ALTER TABLE admin_user ADD COLUMN {name} {ddl}")


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

# 人工黑白名单内存缓存（10 万终端性能项）：
# get_enabled_list 原为每查询两次全表 SELECT，高 QPS 下 20 检测线程
# 全部挤在 SQLite 读锁上（py-spy 实证 2026-08-28）。名单变更频率极低
# （人工操作），检测读取频率极高——内存缓存 + 变更点失效是最优结构。
# 缓存值为 list（_match_domain/_match_ip 直接线性遍历，语义不变）。
_LIST_CACHE: dict[tuple[str, str], list[str]] = {}
_LIST_CACHE_LOCK = threading.Lock()


def invalidate_list_cache() -> None:
    """名单数据变更后调用：清空缓存（下次查询重建）。"""
    with _LIST_CACHE_LOCK:
        _LIST_CACHE.clear()


def get_enabled_list(list_type: str, target: str) -> list[str]:
    """读取启用的名单条目（detectors.match_list 用，带内存缓存）。

    返回的 list 是缓存内部对象——调用方只读不修改（检测主流程
    仅遍历匹配，无修改场景）。
    """
    key = (list_type, target)
    with _LIST_CACHE_LOCK:
        cached = _LIST_CACHE.get(key)
    if cached is not None:
        return cached
    with db_cursor() as cur:
        cur.execute(
            "SELECT value FROM filter_list WHERE list_type=? AND target=? AND enabled=1",
            (list_type, target),
        )
        values = [row["value"] for row in cur.fetchall()]
    with _LIST_CACHE_LOCK:
        _LIST_CACHE[key] = values
    return values


def get_system_config(key: str, default: str = "") -> str:
    with db_cursor() as cur:
        cur.execute("SELECT value FROM system_config WHERE key=?", (key,))
        row = cur.fetchone()
        return row["value"] if row else default
