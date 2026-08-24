"""操作审计查询（PRD 7.2 审计）。"""

from fastapi import APIRouter, Depends, Query

from app.auth import get_current_user
from app.db import db_cursor

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
def query_audit(
    start: str | None = None,
    end: str | None = None,
    operator: str | None = None,
    action: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    _: str = Depends(get_current_user),
):
    # TODO(AI): 分页查询 audit_log
    return {"code": 0, "message": "ok",
            "data": {"total": 0, "items": []}}
