"""AI 旁路分析接口（迭代 49 · AI 能力规划 P0-5）。

只读接口为主：AI 结论查询、DGA/隧道便捷视图、模块状态概览。
唯一的写接口是结论状态更新（确认/忽略）——**加白等实际动作
仍走名单接口，由人工显式操作**（红线：AI 只出建议）。

前端契约统一 {code, message, data}（与既有 router 一致）。
"""

import json

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth import get_current_user
from app.audit import write_audit
from app.db import db_cursor

import ai_batch
import ai_collector

router = APIRouter(prefix="/api/ai", tags=["ai"])

_VALID_TYPES = ("dga_suspect", "tunnel_suspect", "false_positive",
                "threat_cluster", "client_anomaly")
_VALID_STATUS = ("pending", "confirmed", "dismissed")


def _finding_rows(cur, rows) -> list[dict]:
    out = []
    for r in rows:
        try:
            ev = json.loads(r["evidence"]) if r["evidence"] else {}
        except (ValueError, TypeError):
            ev = {}
        out.append({
            "id": r["id"], "type": r["type"], "target": r["target"],
            "score": r["score"], "evidence": ev, "status": r["status"],
            "created_at": r["created_at"], "updated_at": r["updated_at"],
        })
    return out


@router.get("/findings")
def list_findings(type: str | None = Query(None),
                  status: str = Query("pending"),
                  min_score: float = Query(0.0, ge=0.0, le=1.0),
                  limit: int = Query(50, ge=1, le=500),
                  offset: int = Query(0, ge=0),
                  _: str = Depends(get_current_user)):
    """AI 结论查询（按类型/状态/最低分过滤，分页）。"""
    where, params = ["1=1"], []
    if type:
        if type not in _VALID_TYPES:
            raise HTTPException(400, f"未知类型：{type}")
        where.append("type=?")
        params.append(type)
    if status:
        if status not in _VALID_STATUS:
            raise HTTPException(400, f"未知状态：{status}")
        where.append("status=?")
        params.append(status)
    if min_score > 0:
        where.append("score>=?")
        params.append(min_score)
    cond = " AND ".join(where)
    with db_cursor() as cur:
        cur.execute(f"SELECT COUNT(*) AS n FROM ai_findings WHERE {cond}",
                    params)
        total = cur.fetchone()["n"]
        cur.execute(
            f"""SELECT * FROM ai_findings WHERE {cond}
                ORDER BY score DESC, created_at DESC LIMIT ? OFFSET ?""",
            params + [limit, offset])
        items = _finding_rows(cur, cur.fetchall())
    return {"code": 0, "message": "ok",
            "data": {"total": total, "items": items}}


@router.get("/dga-suspects")
def dga_suspects(limit: int = Query(50, ge=1, le=500),
                 min_score: float = Query(0.0, ge=0.0, le=1.0),
                 _: str = Depends(get_current_user)):
    """疑似 DGA 域名清单（便捷视图）。"""
    with db_cursor() as cur:
        cur.execute(
            """SELECT * FROM ai_findings WHERE type='dga_suspect'
               AND status='pending' AND score>=?
               ORDER BY score DESC, created_at DESC LIMIT ?""",
            (min_score, limit))
        items = _finding_rows(cur, cur.fetchall())
    return {"code": 0, "message": "ok", "data": {"items": items}}


@router.get("/tunnel-suspects")
def tunnel_suspects(limit: int = Query(50, ge=1, le=500),
                    min_score: float = Query(0.0, ge=0.0, le=1.0),
                    _: str = Depends(get_current_user)):
    """疑似 DNS 隧道会话清单（target 形如 <client>|<parent_domain>）。"""
    with db_cursor() as cur:
        cur.execute(
            """SELECT * FROM ai_findings WHERE type='tunnel_suspect'
               AND status='pending' AND score>=?
               ORDER BY score DESC, created_at DESC LIMIT ?""",
            (min_score, limit))
        items = _finding_rows(cur, cur.fetchall())
    return {"code": 0, "message": "ok", "data": {"items": items}}


@router.post("/findings/{finding_id}/status")
def update_finding_status(finding_id: int, status: str = Query(...),
                          user: str = Depends(get_current_user)):
    """确认/忽略某条结论（人工研判留痕，不直接改变拦截策略）。"""
    if status not in ("confirmed", "dismissed"):
        raise HTTPException(400, "status 仅支持 confirmed / dismissed")
    with db_cursor() as cur:
        cur.execute("SELECT type, target FROM ai_findings WHERE id=?",
                    (finding_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "结论不存在")
        cur.execute(
            "UPDATE ai_findings SET status=?, "
            "updated_at=datetime('now','localtime') WHERE id=?",
            (status, finding_id))
    write_audit(user, "ai_finding_status",
                {"id": finding_id, "type": row["type"],
                 "target": row["target"], "status": status})
    return {"code": 0, "message": "ok", "data": {"id": finding_id,
                                                 "status": status}}


@router.get("/stats")
def ai_stats(_: str = Depends(get_current_user)):
    """AI 模块状态概览（首现表规模、结论统计、采集/批处理运行状态）。"""
    with db_cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM domain_first_seen")
        fs_total = cur.fetchone()["n"]
        cur.execute("SELECT COUNT(*) AS n FROM domain_first_seen "
                    "WHERE first_seen >= datetime('now','localtime','-24 hours')")
        fs_24h = cur.fetchone()["n"]
        cur.execute("SELECT type, status, COUNT(*) AS n FROM ai_findings "
                    "GROUP BY type, status")
        findings = {}
        for r in cur.fetchall():
            findings.setdefault(r["type"], {})[r["status"]] = r["n"]
    return {"code": 0, "message": "ok", "data": {
        "first_seen_total": fs_total,
        "first_seen_24h": fs_24h,
        "findings": findings,
        "collector": ai_collector.stats(),
        "batch": ai_batch.last_run(),
    }}
