"""过滤日志查询 + 导出（PRD 7.2 过滤日志，字段见 PRD 5.5）。"""

import csv
import io

from fastapi import APIRouter, Depends, Query, Response

from app.auth import get_current_user
from app.db import db_cursor

router = APIRouter(prefix="/api/logs", tags=["logs"])

_LOG_COLUMNS = ("id", "timestamp", "client_ip", "domain", "query_type",
                "filter_reason", "action", "malicious_ips", "final_result",
                "source_api")


def _build_condition(start: str | None, end: str | None, client_ip: str | None,
                     domain: str | None, action: str | None,
                     reason: str | None) -> tuple[str, list]:
    """构造 WHERE 子句（日志与导出共用）。"""
    where, params = [], []
    if start:
        where.append("timestamp>=?"); params.append(start)
    if end:
        where.append("timestamp<=?"); params.append(end)
    if client_ip:
        where.append("client_ip LIKE ?"); params.append(f"%{client_ip}%")
    if domain:
        where.append("domain LIKE ?"); params.append(f"%{domain}%")
    if action:
        where.append("action=?"); params.append(action)
    if reason:
        where.append("filter_reason LIKE ?"); params.append(f"%{reason}%")
    cond = ("WHERE " + " AND ".join(where)) if where else ""
    return cond, params


@router.get("")
def query_logs(
    start: str | None = None,
    end: str | None = None,
    client_ip: str | None = None,
    domain: str | None = None,
    action: str | None = None,
    reason: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    _: str = Depends(get_current_user),
):
    """查询过滤日志（PRD 5.5：时间/客户端IP/域名/原因/动作 多条件筛选）。"""
    cond, params = _build_condition(start, end, client_ip, domain, action, reason)
    with db_cursor() as cur:
        cur.execute(f"SELECT COUNT(*) AS c FROM filter_log {cond}", params)
        total = cur.fetchone()["c"]
        cur.execute(
            f"""SELECT {','.join(_LOG_COLUMNS)} FROM filter_log {cond}
                ORDER BY id DESC LIMIT ? OFFSET ?""",
            params + [size, (page - 1) * size],
        )
        items = [dict(r) for r in cur.fetchall()]
    return {"code": 0, "message": "ok", "data": {"total": total, "items": items}}


@router.get("/export")
def export_logs(
    start: str | None = None,
    end: str | None = None,
    client_ip: str | None = None,
    domain: str | None = None,
    action: str | None = None,
    reason: str | None = None,
    _: str = Depends(get_current_user),
):
    """导出 CSV（utf-8-sig 带 BOM，含 client_ip 列）。"""
    cond, params = _build_condition(start, end, client_ip, domain, action, reason)
    with db_cursor() as cur:
        cur.execute(
            f"""SELECT {','.join(_LOG_COLUMNS)} FROM filter_log {cond}
                ORDER BY id DESC LIMIT 100000""",
            params,
        )
        rows = cur.fetchall()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_LOG_COLUMNS)
    for r in rows:
        writer.writerow([r[c] for c in _LOG_COLUMNS])

    return Response(
        content=buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="filter_log.csv"'},
    )
