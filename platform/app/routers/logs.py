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


@router.get("/reasons")
def list_reason_options(_: str = Depends(get_current_user)):
    """过滤原因筛选下拉选项（迭代 39：过滤日志页原因筛选）。

    分三组返回，前端据此渲染 optgroup：
    - fixed：四类固定原因（local_blacklist / threat_list:* / ip_filter /
      threatintel:*），fixed 组用精确匹配语义（见 _build_condition）；
    - online：已启用的在线情报源名（threatintel:reason LIKE 匹配
      "threatintel:%:src" 中的源名段）；
    - offline：已启用的离线大名单源 key（直查 threat_list 表
      DISTINCT source WHERE enabled=1，含自定义源；显示名取内置
      元数据、自定义源回退 key），筛选 threat_list:<key> 用 LIKE
      前缀匹配——兼容迭代 39 前的裸 threat_list 旧数据。
    """
    from app import threat_list
    with db_cursor() as cur:
        cur.execute("SELECT name, enabled FROM threatintel_api ORDER BY id")
        online = [dict(r) for r in cur.fetchall()]
    # offline 直查 threat_list 表（enabled_source_keys 含自定义源，
    # 不受 source_stats 仅内置 SOURCES 的限制）；显示名关联内置元数据，
    # 自定义源回退原始 key
    meta = {s["key"]: s["name"] for s in threat_list.SOURCES}
    offline = [{"key": k, "label": meta.get(k, k)}
               for k in sorted(threat_list.enabled_source_keys())]
    return {"code": 0, "message": "ok", "data": {
        "fixed": [
            {"key": "local_blacklist", "label": "人工黑名单"},
            {"key": "threat_list", "label": "离线情报源（全部）"},
            {"key": "ip_filter", "label": "IP 后置过滤"},
            {"key": "threatintel", "label": "在线情报（全部）"},
        ],
        "online": [{"key": r["name"], "label": r["name"]}
                   for r in online if r["enabled"]],
        "offline": offline,
    }}


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


@router.get("/stream")
def stream_intercepts(size: int = Query(8, ge=1, le=50),
                      _: str = Depends(get_current_user)):
    """实时拦截事件流（SOC 大屏 3s 轮询专用，Task #175 迭代 28）。

    与 /api/logs 的差异（为高频轮询专门瘦身）：
    - 只取拦截/剔除（安全事件），不混 allow 采样日志；
    - 不做 COUNT(*) 全表统计（大库下 3s 一次不可接受）；
    - ORDER BY id DESC + 主键索引，开销 O(size)。

    旧口径问题：前端轮询 /api/logs?size=8 无 action 过滤，放行日志
    开启采样后会混入事件流且被渲染成"拦截"——语义错误。
    """
    with db_cursor() as cur:
        cur.execute(
            f"""SELECT {','.join(_LOG_COLUMNS)} FROM filter_log
                WHERE action IN ('intercept','remove_ip')
                ORDER BY id DESC LIMIT ?""",
            (size,),
        )
        items = [dict(r) for r in cur.fetchall()]
    return {"code": 0, "message": "ok", "data": {"items": items}}


@router.get("/agg/domains")
def aggregate_domains(
    start: str | None = None,
    end: str | None = None,
    domain: str | None = None,
    action: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    _: str = Depends(get_current_user),
):
    """按域名聚合的过滤统计（迭代 37 域名分析页）。

    用途：过滤日志日增几十万条，明细难定位——本视图按域名 GROUP BY
    给出拦截/剔除/放行计数、拦截来源构成、首末次时间，支撑"某域名
    为什么被拦 / 拦了多少"的针对性排查。

    实现说明：
    - 复用 /api/logs 的筛选语义（start/end 时间窗、domain 模糊、action）；
    - WHERE + GROUP BY domain 走 idx_log_domain/domain 索引扫描，
      时间窗过滤后聚合（生产 90 天 4500 万行场景建议收窄时间窗）；
    - reason_top：GROUP BY 域内取该域名计数最高的 3 个 filter_reason，
      用窗口函数 row_number()（SQLite 3.25+），展示"它因什么被拦"；
    - 分页在聚合结果上进行（HAVING 后 LIMIT/OFFSET）。
    """
    cond, params = _build_condition(start, end, None, domain, action, None)
    with db_cursor() as cur:
        # 聚合主体：每域名一行
        cur.execute(
            f"""SELECT domain,
                       COUNT(*)                       AS total,
                       SUM(CASE WHEN action='intercept'  THEN 1 ELSE 0 END) AS intercepts,
                       SUM(CASE WHEN action='remove_ip' THEN 1 ELSE 0 END) AS removes,
                       SUM(CASE WHEN action='allow'     THEN 1 ELSE 0 END) AS allows,
                       MIN(timestamp)                 AS first_seen,
                       MAX(timestamp)                 AS last_seen
                FROM filter_log {cond}
                GROUP BY domain
                ORDER BY total DESC, domain ASC
                LIMIT ? OFFSET ?""",
            params + [size, (page - 1) * size],
        )
        rows = [dict(r) for r in cur.fetchall()]

        # 每域名 Top3 拦截原因（一次查询取回后内存分组，避免逐行 N+1）
        if rows:
            domains = [r["domain"] for r in rows]
            ph = ",".join("?" * len(domains))
            cond2 = (cond + " AND" if cond else "WHERE") + f" domain IN ({ph})"
            cur.execute(
                f"""SELECT domain, filter_reason, COUNT(*) AS c,
                           ROW_NUMBER() OVER (
                               PARTITION BY domain
                               ORDER BY COUNT(*) DESC, filter_reason ASC
                           ) AS rn
                    FROM filter_log {cond2}
                    GROUP BY domain, filter_reason
                    ORDER BY domain, c DESC
                    """,
                params + domains,
            )
            reason_map: dict[str, list] = {}
            for r in cur.fetchall():
                if r["rn"] <= 3:
                    reason_map.setdefault(r["domain"], []).append(
                        {"reason": r["filter_reason"], "count": r["c"]})
        else:
            reason_map = {}

        # 聚合行数（分页总数）：聚合后再数一遍，仅 GROUP BY 无排序开销
        cur.execute(
            f"SELECT COUNT(*) AS c FROM (SELECT domain FROM filter_log {cond} GROUP BY domain)",
            params,
        )
        agg_total = cur.fetchone()["c"]

    items = []
    for r in rows:
        r["reason_top"] = reason_map.get(r["domain"], [])
        items.append(r)
    return {"code": 0, "message": "ok",
            "data": {"total": agg_total, "items": items}}


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
