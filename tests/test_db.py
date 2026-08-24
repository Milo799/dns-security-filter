"""数据库 schema 完整性测试：建表 SQL 可执行且 6 张表齐全（PRD 第六章）。"""

import sqlite3
from pathlib import Path

SCHEMA = Path(__file__).parent.parent / "platform" / "app" / "schema.sql"

EXPECTED_TABLES = {
    "filter_list", "threatintel_api", "filter_log",
    "admin_user", "system_config", "audit_log",
}


def test_schema_executes_and_has_all_tables():
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    tables = {r[0] for r in rows}
    assert EXPECTED_TABLES <= tables
    conn.close()


def test_filter_log_has_client_ip_column():
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    cols = {r[1] for r in conn.execute("PRAGMA table_info(filter_log)")}
    assert "client_ip" in cols  # PRD V1.1 新增：日志含客户端 IP
    conn.close()
