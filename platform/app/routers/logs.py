"""过滤日志查询 + 导出（PRD 7.2 过滤日志）。"""

from fastapi import APIRouter, Depends, Query

from app.auth import get_current_user
from app.db import db_cursor

router = APIRouter(prefix="/api/logs", tags=["logs"])


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
    # TODO(AI): 按条件分页查询 filter_log，返回 total + items
    return {"code": 0, "message": "ok",
            "data": {"total": 0, "items": []}}


@router.get("/export")
def export_logs(
    start: str | None = None,
    end: str | None = None,
    client_ip: str | None = None,
    _: str = Depends(get_current_user),
):
    """导出 CSV（Content-Disposition: attachment）。"""
    # TODO(AI): 导出 filter_log 为 CSV（含 client_ip 列）
    return {"code": 0, "message": "ok", "data": {}}
