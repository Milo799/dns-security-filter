"""操作审计查询（PRD 7.2 审计）。"""

import json

from fastapi import APIRouter, Depends, Query

from app.audit import humanize
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

        # 解析 detail + 收集需要补名的 id
        parsed = []
        list_ids, ti_ids = set(), set()
        for it in items:
            try:
                d = json.loads(it["detail"]) if it["detail"] else {}
            except Exception:
                d = {}
            if not isinstance(d, dict):
                d = {}
            parsed.append(d)
            if it["action"] in ("list_create", "list_update", "list_delete") \
                    and isinstance(d.get("id"), int):
                list_ids.add(d["id"])
            if it["action"] == "threatintel_update" \
                    and isinstance(d.get("id"), int):
                ti_ids.add(d["id"])

        # 批量预查名单条目名（create/delete 自带 value，但 update 只有 id）
        list_map = {}
        if list_ids:
            ph = ",".join("?" * len(list_ids))
            for r in cur.execute(
                f"SELECT id, value, list_type, target FROM filter_list "
                f"WHERE id IN ({ph})", tuple(list_ids),
            ):
                list_map[r["id"]] = dict(r)

        # 批量预查情报源名（update 只有 id 无 name）
        ti_map = {}
        if ti_ids:
            ph = ",".join("?" * len(ti_ids))
            for r in cur.execute(
                f"SELECT id, name, adapter_type FROM threatintel_api "
                f"WHERE id IN ({ph})", tuple(ti_ids),
            ):
                ti_map[r["id"]] = dict(r)

    for it, d in zip(items, parsed):
        it["readable"] = humanize(it["action"], d, list_map, ti_map)

    return {"code": 0, "message": "ok", "data": {"total": total, "items": items}}
