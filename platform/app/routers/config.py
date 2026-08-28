"""系统配置读写 + 平台状态 + 检测总开关（PRD 7.2 系统配置/状态）。

修改配置经 app.runtime.set_config 同时写 DB 与内存 CONFIG，
DNS 引擎（detectors 每次查询读 CONFIG）立即热生效。
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth import get_current_user
from app.audit import write_audit
from app.db import db_cursor
from app.runtime import set_config

router = APIRouter(prefix="/api", tags=["config"])

VALID_STRATEGIES = {"any", "majority", "all"}


class ConfigBody(BaseModel):
    alert_ip: str | None = None
    alert_ttl: int | None = None
    upstream_dns: str | None = None
    fusion_strategy: str | None = None
    log_retention_days: int | None = None
    allow_log_enabled: bool | None = None
    threatlist_auto_update: bool | None = None
    threatlist_auto_interval_hours: int | None = None
    domain_cache_ttl_s: int | None = None
    domain_cache_size: int | None = None


@router.get("/config")
def read_config(_: str = Depends(get_current_user)):
    """读取 system_config 全部键值（供 Web 界面展示）。"""
    with db_cursor() as cur:
        cur.execute(
            "SELECT key, value, updated_at FROM system_config ORDER BY key"
        )
        items = {r["key"]: {"value": r["value"],
                            "updated_at": r["updated_at"]}
                 for r in cur.fetchall()}
    return {"code": 0, "message": "ok", "data": {"items": items}}


@router.put("/config")
def update_config(body: ConfigBody, user: str = Depends(get_current_user)):
    """逐键更新（至少一项）。布尔转 '1'/'0'，整数转字符串存库。"""
    data = body.model_dump(exclude_none=True)
    if not data:
        raise HTTPException(status_code=400, detail="没有需要更新的配置项")
    if "fusion_strategy" in data and data["fusion_strategy"] not in VALID_STRATEGIES:
        raise HTTPException(status_code=400,
                            detail="fusion_strategy 必须为 any/majority/all")
    if "alert_ttl" in data and not (1 <= data["alert_ttl"] <= 86400):
        raise HTTPException(status_code=400, detail="alert_ttl 须在 1~86400 之间")
    if "log_retention_days" in data and not (1 <= data["log_retention_days"] <= 3650):
        raise HTTPException(status_code=400, detail="log_retention_days 须在 1~3650 之间")
    if "threatlist_auto_interval_hours" in data and not (
            1 <= data["threatlist_auto_interval_hours"] <= 720):
        raise HTTPException(
            status_code=400,
            detail="threatlist_auto_interval_hours 须在 1~720 之间（1 小时~30 天）")
    if "domain_cache_ttl_s" in data and not (1 <= data["domain_cache_ttl_s"] <= 86400):
        raise HTTPException(
            status_code=400, detail="domain_cache_ttl_s 须在 1~86400 之间（秒）")
    if "domain_cache_size" in data and not (1024 <= data["domain_cache_size"] <= 10_000_000):
        raise HTTPException(
            status_code=400,
            detail="domain_cache_size 须在 1024~10000000 之间（条）")

    changes = {}
    for key, value in data.items():
        set_config(key, str(int(value)) if isinstance(value, bool) else str(value))
        changes[key] = value
    write_audit(user, "config_update", changes)
    return {"code": 0, "message": "ok", "data": {"updated": changes}}


@router.get("/status")
def platform_status(_: str = Depends(get_current_user)):
    """平台运行状态：检测开关、今日拦截/放行计数、情报源状态。"""
    with db_cursor() as cur:
        cur.execute(
            """SELECT
                 SUM(CASE WHEN action='intercept' THEN 1 ELSE 0 END) AS intercepts,
                 SUM(CASE WHEN action='remove_ip'  THEN 1 ELSE 0 END) AS removes,
                 SUM(CASE WHEN action='allow'     THEN 1 ELSE 0 END) AS allows
               FROM filter_log
               WHERE date(timestamp)=date('now','localtime')"""
        )
        row = cur.fetchone()
        cur.execute(
            """SELECT name, enabled FROM threatintel_api ORDER BY id"""
        )
        sources = [dict(r) for r in cur.fetchall()]

    with db_cursor() as cur:
        cur.execute("SELECT value FROM system_config WHERE key='detection_enabled'")
        detection = cur.fetchone()["value"] == "1"

    intercepts = row["intercepts"] or 0
    removes = row["removes"] or 0
    allows = row["allows"] or 0
    return {"code": 0, "message": "ok", "data": {
        "detection_enabled": detection,
        "today_intercepts": intercepts,
        "today_removes": removes,
        "today_allows": allows,
        "today_total": intercepts + removes + allows,
        "threatintel_sources": sources,
    }}


@router.get("/status/trend")
def status_trend(days: int = 7, _: str = Depends(get_current_user)):
    """近 N 日拦截/剔除趋势（仪表盘图表用）。"""
    days = max(1, min(days, 90))
    with db_cursor() as cur:
        cur.execute(
            """SELECT date(timestamp) AS day,
                 SUM(CASE WHEN action='intercept' THEN 1 ELSE 0 END) AS intercepts,
                 SUM(CASE WHEN action='remove_ip'  THEN 1 ELSE 0 END) AS removes
               FROM filter_log
               WHERE timestamp >= datetime('now', ?)
               GROUP BY date(timestamp) ORDER BY day""",
            (f"-{days} days",),
        )
        items = [dict(r) for r in cur.fetchall()]
    return {"code": 0, "message": "ok", "data": {"days": days, "items": items}}


@router.get("/status/hourly")
def status_hourly(hours: int = 24, _: str = Depends(get_current_user)):
    """近 N 小时拦截/剔除聚合（SOC 大屏：24h 柱线图与热力图共用）。

    hour 为完整 'YYYY-MM-DD HH:00'（跨天不合并），前端取 slice(11,16)。
    intercepts/removes 供柱线图；四类来源列供小时×来源热力图。
    """
    hours = max(1, min(hours, 168))
    with db_cursor() as cur:
        cur.execute(
            """SELECT strftime('%Y-%m-%d %H:00', timestamp) AS hour,
                 SUM(CASE WHEN action='intercept' THEN 1 ELSE 0 END) AS intercepts,
                 SUM(CASE WHEN action='remove_ip'  THEN 1 ELSE 0 END) AS removes,
                 SUM(CASE WHEN filter_reason='local_blacklist' THEN 1 ELSE 0 END)
                   AS local_blacklist,
                 SUM(CASE WHEN filter_reason='threat_list' THEN 1 ELSE 0 END)
                   AS threat_list,
                 SUM(CASE WHEN filter_reason LIKE 'threatintel:%' THEN 1 ELSE 0 END)
                   AS threatintel,
                 SUM(CASE WHEN filter_reason='ip_filter' THEN 1 ELSE 0 END)
                   AS ip_filter
               FROM filter_log
               WHERE timestamp >= datetime('now','localtime', ?)
               GROUP BY hour ORDER BY hour""",
            (f"-{hours} hours",),
        )
        items = [dict(r) for r in cur.fetchall()]
    return {"code": 0, "message": "ok",
            "data": {"hours": hours, "items": items}}


@router.get("/status/breakdown")
def status_breakdown(days: int = 7, top: int = 10,
                     _: str = Depends(get_current_user)):
    """拦截来源构成 + Top 拦截域名（仪表盘态势图用，只读）。

    来源按 filter_reason 前缀归类：
      local_blacklist → 本地黑名单；threat_list → 离线大名单；
      threatintel:*   → 在线情报；  ip_filter      → IP 后置过滤。
    """
    days = max(1, min(days, 90))
    top = max(1, min(top, 50))
    with db_cursor() as cur:
        cur.execute(
            """SELECT
                 SUM(CASE WHEN filter_reason='local_blacklist'
                     THEN 1 ELSE 0 END) AS local_blacklist,
                 SUM(CASE WHEN filter_reason='threat_list'
                     THEN 1 ELSE 0 END) AS threat_list,
                 SUM(CASE WHEN filter_reason LIKE 'threatintel:%'
                     THEN 1 ELSE 0 END) AS threatintel,
                 SUM(CASE WHEN filter_reason='ip_filter'
                     THEN 1 ELSE 0 END) AS ip_filter
               FROM filter_log
               WHERE timestamp >= datetime('now', ?)""",
            (f"-{days} days",),
        )
        row = cur.fetchone()
        sources = [
            {"key": "local_blacklist", "label": "本地黑名单",
             "count": row["local_blacklist"] or 0},
            {"key": "threat_list", "label": "离线大名单",
             "count": row["threat_list"] or 0},
            {"key": "threatintel", "label": "在线情报",
             "count": row["threatintel"] or 0},
            {"key": "ip_filter", "label": "IP 后置",
             "count": row["ip_filter"] or 0},
        ]
        cur.execute(
            """SELECT domain, COUNT(*) AS cnt FROM filter_log
               WHERE timestamp >= datetime('now', ?)
                 AND action IN ('intercept','remove_ip')
               GROUP BY domain ORDER BY cnt DESC LIMIT ?""",
            (f"-{days} days", top),
        )
        top_domains = [{"domain": r["domain"], "count": r["cnt"]}
                       for r in cur.fetchall()]
        cur.execute(
            """SELECT client_ip, COUNT(*) AS cnt FROM filter_log
               WHERE timestamp >= datetime('now','localtime', ?)
                 AND action IN ('intercept','remove_ip')
                 AND client_ip != ''
               GROUP BY client_ip ORDER BY cnt DESC LIMIT ?""",
            (f"-{days} days", top),
        )
        top_clients = [{"client_ip": r["client_ip"], "count": r["cnt"]}
                       for r in cur.fetchall()]
    return {"code": 0, "message": "ok",
            "data": {"days": days, "sources": sources,
                     "top_domains": top_domains,
                     "top_clients": top_clients}}


@router.get("/domain-cache/stats")
def domain_cache_stats(_: str = Depends(get_current_user)):
    """域名检测结论缓存状态：条目数/容量/命中数/命中率。

    压测观测与运维巡检用；进程内累计，重启归零。
    """
    import domain_cache
    return {"code": 0, "message": "ok", "data": domain_cache.stats()}


@router.post("/detection/toggle")
def toggle_detection(body: dict, user: str = Depends(get_current_user)):
    """切换检测总开关；关闭时全部请求直接放行（操作留痕）。"""
    enabled = bool(body.get("enabled"))
    set_config("detection_enabled", str(int(enabled)))
    write_audit(user, "detection_toggle", {"enabled": enabled})
    return {"code": 0, "message": "ok",
            "data": {"detection_enabled": enabled}}
