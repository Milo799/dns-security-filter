"""操作审计写入辅助（audit_log 表，PRD 6.6）。

所有敏感操作（名单变更、检测开关、情报源启停、配置修改）统一经
write_audit 落库，Web 审计页面可查。
"""

import json

from app.db import db_cursor


def write_audit(operator: str, action: str, detail: dict) -> None:
    """写一条审计记录。detail 为可 JSON 序列化的变更内容。"""
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO audit_log (operator, action, detail) VALUES (?, ?, ?)",
            (operator, action, json.dumps(detail, ensure_ascii=False)),
        )
