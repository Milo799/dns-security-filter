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

    return {"code": 0, "message": "ok", "data": {
        "detection_enabled": detection,
        "today_intercepts": row["intercepts"] or 0,
        "today_removes": row["removes"] or 0,
        "today_allows": row["allows"] or 0,
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


@router.post("/detection/toggle")
def toggle_detection(body: dict, user: str = Depends(get_current_user)):
    """切换检测总开关；关闭时全部请求直接放行（操作留痕）。"""
    enabled = bool(body.get("enabled"))
    set_config("detection_enabled", str(int(enabled)))
    write_audit(user, "detection_toggle", {"enabled": enabled})
    return {"code": 0, "message": "ok",
            "data": {"detection_enabled": enabled}}
