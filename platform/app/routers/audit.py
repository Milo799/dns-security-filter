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
    where, params = [], []
    if start:
        where.append("timestamp>=?"); params.append(start)
    if end:
        where.append("timestamp<=?"); params.append(end)
    if operator:
        where.append("operator=?"); params.append(operator)
    if action:
        where.append("action=?"); params.append(action)
    cond = ("WHERE " + " AND ".join(where)) if where else ""

    with db_cursor() as cur:
        cur.execute(f"SELECT COUNT(*) AS c FROM audit_log {cond}", params)
        total = cur.fetchone()["c"]
        cur.execute(
            f"""SELECT * FROM audit_log {cond}
                ORDER BY id DESC LIMIT ? OFFSET ?""",
            params + [size, (page - 1) * size],
        )
        items = [dict(r) for r in cur.fetchall()]
    return {"code": 0, "message": "ok", "data": {"total": total, "items": items}}
