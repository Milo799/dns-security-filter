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
                "threat_cluster", "client_anomaly", "intel_quality")
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


@router.get("/false-positive")
def false_positive_list(limit: int = Query(50, ge=1, le=500),
                        min_score: float = Query(0.0, ge=0.0, le=1.0),
                        _: str = Depends(get_current_user)):
    """疑似误伤清单（多客户端共访等业务特征；加白需人工确认）。

    附带的 evidence 含各特征贡献分，便于快速判断"该不该加白"。
    """
    with db_cursor() as cur:
        cur.execute(
            """SELECT * FROM ai_findings WHERE type='false_positive'
               AND status='pending' AND score>=?
               ORDER BY score DESC, created_at DESC LIMIT ?""",
            (min_score, limit))
        items = _finding_rows(cur, cur.fetchall())
        # 标注哪些已在白名单（防重复加白）
        if items:
            vals = [i["target"] for i in items]
            marks = ",".join("?" * len(vals))
            cur.execute(
                f"""SELECT value FROM filter_list WHERE list_type='whitelist'
                    AND target='domain' AND value IN ({marks})""", vals)
            already = {r["value"] for r in cur.fetchall()}
            for i in items:
                i["already_whitelisted"] = i["target"] in already
    return {"code": 0, "message": "ok", "data": {"items": items}}


@router.post("/false-positive/{domain}/whitelist")
def confirm_whitelist(domain: str, remark: str = Query(""),
                      user: str = Depends(get_current_user)):
    """一键加白（**人工确认后**执行）——AI 只出建议，此接口由人点击触发。

    写白名单 + 失效名单缓存（DNS 进程经 cross_sync 60s 内同步）
    + 标记对应误报结论为 confirmed + 审计留痕。
    """
    d = (domain or "").strip().lower().rstrip(".")
    if not d or "." not in d:
        raise HTTPException(400, "域名格式非法")
    with db_cursor() as cur:
        cur.execute(
            """SELECT id FROM filter_list WHERE list_type='whitelist'
               AND target='domain' AND value=? LIMIT 1""", (d,))
        if cur.fetchone():
            raise HTTPException(409, "该域名已在白名单中")
        cur.execute(
            """INSERT INTO filter_list (list_type, target, value, enabled,
                                        remark, created_by)
               VALUES ('whitelist', 'domain', ?, 1, ?, ?)""",
            (d, remark or "AI 误报识别建议 · 人工确认加白", user))
        cur.execute(
            """UPDATE ai_findings SET status='confirmed',
                   updated_at=datetime('now','localtime')
               WHERE type='false_positive' AND target=?
                 AND status='pending'""", (d,))
    from app.db import invalidate_list_cache
    invalidate_list_cache()
    write_audit(user, "ai_false_positive_whitelist",
                {"domain": d, "remark": remark})
    return {"code": 0, "message": "ok", "data": {"domain": d,
                                                 "whitelisted": True}}


@router.get("/threat-clusters")
def threat_clusters(limit: int = Query(50, ge=1, le=500),
                    min_score: float = Query(0.0, ge=0.0, le=1.0),
                    _: str = Depends(get_current_user)):
    """威胁族群榜单（target = 可注册父域；按规模归一评分排序）。

    evidence 含族群画像：拦截次数、独立域名数、客户端数、命中源分布、
    样例域名——用于快速了解"今天被攻击的基础设施有哪些"。
    """
    with db_cursor() as cur:
        cur.execute(
            """SELECT * FROM ai_findings WHERE type='threat_cluster'
               AND status='pending' AND score>=?
               ORDER BY score DESC, created_at DESC LIMIT ?""",
            (min_score, limit))
        items = _finding_rows(cur, cur.fetchall())
    return {"code": 0, "message": "ok", "data": {"items": items}}


@router.get("/client-anomalies")
def client_anomalies(limit: int = Query(50, ge=1, le=500),
                     min_score: float = Query(0.0, ge=0.0, le=1.0),
                     _: str = Depends(get_current_user)):
    """客户端行为异常榜（失陷主机嫌疑）。

    evidence 含新域名规模/拦截命中/父域分散度及各特征贡献——判读"这台
    机器是否失陷"的依据。仅输出嫌疑，不自动处置。
    """
    with db_cursor() as cur:
        cur.execute(
            """SELECT * FROM ai_findings WHERE type='client_anomaly'
               AND status='pending' AND score>=?
               ORDER BY score DESC, created_at DESC LIMIT ?""",
            (min_score, limit))
        items = _finding_rows(cur, cur.fetchall())
    return {"code": 0, "message": "ok", "data": {"items": items}}


@router.get("/intel-quality")
def intel_quality(_: str = Depends(get_current_user)):
    """情报源质量评分（按命中贡献）。

    evidence 含命中数/条目数/命中密度（每万条命中）——条目多但从不命中
    的源可据此评估停用。按 score 降序。
    """
    with db_cursor() as cur:
        cur.execute(
            """SELECT * FROM ai_findings WHERE type='intel_quality'
               ORDER BY score DESC""")
        items = _finding_rows(cur, cur.fetchall())
    return {"code": 0, "message": "ok", "data": {"items": items}}


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
