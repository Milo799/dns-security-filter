"""系统配置读写 + 平台状态 + 检测总开关（PRD 7.2 系统配置/状态）。

修改配置经 app.runtime.set_config 同时写 DB 与内存 CONFIG，
DNS 引擎（detectors 每次查询读 CONFIG）立即热生效。
"""

import time
import urllib.parse

from datetime import date

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth import get_current_user
from app.audit import write_audit
from app.db import db_cursor
from app.runtime import set_config

router = APIRouter(prefix="/api", tags=["config"])

VALID_STRATEGIES = {"any", "majority", "all"}

# 情报出站代理地址允许的 scheme（白名单；socks 需 httpx[socks] 额外依赖）
PROXY_SCHEMES = {"http", "https"}


def _validate_proxy(value: str) -> str:
    """校验情报出站代理地址；空串合法（停用代理）。返回规范化后的值。"""
    value = (value or "").strip()
    if not value:
        return ""
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme.lower() not in PROXY_SCHEMES:
        raise HTTPException(
            status_code=400,
            detail="代理地址须以 http:// 或 https:// 开头（如 http://172.16.0.10:8080）")
    if not parsed.netloc:
        raise HTTPException(status_code=400, detail="代理地址缺少主机与端口")
    return value


class ConfigBody(BaseModel):
    alert_ip: str | None = None
    alert_ttl: int | None = None
    upstream_dns: str | None = None
    fusion_strategy: str | None = None
    log_retention_days: int | None = None
    allow_log_enabled: bool | None = None
    allow_log_sample_rate: int | None = None
    log_async_enabled: bool | None = None
    log_flush_interval_s: int | None = None
    log_batch_size: int | None = None
    threatlist_auto_update: bool | None = None
    threatlist_auto_interval_hours: int | None = None
    http_proxy: str | None = None
    domain_cache_ttl_s: int | None = None
    domain_cache_size: int | None = None
    ip_cache_ttl_s: int | None = None
    ip_cache_size: int | None = None
    failsafe_mode: str | None = None
    cb_failure_threshold: int | None = None
    cb_open_timeout_s: int | None = None
    degrade_threshold: int | None = None
    degrade_window_s: int | None = None
    upstream_timeout_s: int | None = None
    upstream_failure_threshold: int | None = None
    upstream_open_timeout_s: int | None = None


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
    if "allow_log_sample_rate" in data and not (
            0 <= data["allow_log_sample_rate"] <= 100):
        raise HTTPException(
            status_code=400, detail="allow_log_sample_rate 须在 0~100 之间（百分比，0=不记录）")
    if "log_flush_interval_s" in data and not (
            1 <= data["log_flush_interval_s"] <= 60):
        raise HTTPException(
            status_code=400, detail="log_flush_interval_s 须在 1~60 之间（秒）")
    if "log_batch_size" in data and not (
            100 <= data["log_batch_size"] <= 50000):
        raise HTTPException(
            status_code=400, detail="log_batch_size 须在 100~50000 之间（条）")
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
    if "ip_cache_ttl_s" in data and not (1 <= data["ip_cache_ttl_s"] <= 86400):
        raise HTTPException(
            status_code=400, detail="ip_cache_ttl_s 须在 1~86400 之间（秒）")
    if "ip_cache_size" in data and not (1024 <= data["ip_cache_size"] <= 5_000_000):
        raise HTTPException(
            status_code=400,
            detail="ip_cache_size 须在 1024~5000000 之间（条）")
    if "failsafe_mode" in data and data["failsafe_mode"] not in ("intercept", "degrade"):
        raise HTTPException(
            status_code=400, detail="failsafe_mode 必须为 intercept/degrade")
    if "cb_failure_threshold" in data and not (0 <= data["cb_failure_threshold"] <= 1000):
        raise HTTPException(
            status_code=400, detail="cb_failure_threshold 须在 0~1000 之间（0=禁用熔断）")
    if "cb_open_timeout_s" in data and not (5 <= data["cb_open_timeout_s"] <= 86400):
        raise HTTPException(
            status_code=400, detail="cb_open_timeout_s 须在 5~86400 之间（秒）")
    if "degrade_threshold" in data and not (0 <= data["degrade_threshold"] <= 1000):
        raise HTTPException(
            status_code=400, detail="degrade_threshold 须在 0~1000 之间（0=禁用降级）")
    if "degrade_window_s" in data and not (10 <= data["degrade_window_s"] <= 86400):
        raise HTTPException(
            status_code=400, detail="degrade_window_s 须在 10~86400 之间（秒）")
    if "upstream_timeout_s" in data and not (1 <= data["upstream_timeout_s"] <= 10):
        raise HTTPException(
            status_code=400, detail="upstream_timeout_s 须在 1~10 之间（秒）")
    if "upstream_failure_threshold" in data and not (
            0 <= data["upstream_failure_threshold"] <= 1000):
        raise HTTPException(
            status_code=400,
            detail="upstream_failure_threshold 须在 0~1000 之间（0=禁用上游熔断）")
    if "upstream_open_timeout_s" in data and not (
            5 <= data["upstream_open_timeout_s"] <= 86400):
        raise HTTPException(
            status_code=400, detail="upstream_open_timeout_s 须在 5~86400 之间（秒）")
    if "http_proxy" in data:
        data["http_proxy"] = _validate_proxy(data["http_proxy"])

    changes = {}
    for key, value in data.items():
        set_config(key, str(int(value)) if isinstance(value, bool) else str(value))
        changes[key] = value
    write_audit(user, "config_update", changes)
    return {"code": 0, "message": "ok", "data": {"updated": changes}}


@router.get("/status")
def platform_status(_: str = Depends(get_current_user)):
    """平台运行状态：检测开关、今日拦截/放行计数、情报源状态。

    Task #161：今日请求优先读 dns_query_stats 统计表（DNS 进程内存
    计数周期落库，全量口径不受放行日志采样影响）；表无数据时回退
    filter_log 聚合（旧口径，allows 受 allow_log_enabled 采样低估）。
    """
    # 优先：查询量统计表（全量口径）
    import query_stats
    qs = query_stats.read_today_from_db()
    if qs is not None:
        intercepts = qs["intercept"]
        removes = qs["remove_ip"]
        allows = qs["allow"]
        total = qs["total"]
    else:
        # 回退：filter_log 聚合（历史形态，首次升级部署过渡期）
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
        intercepts = row["intercepts"] or 0
        removes = row["removes"] or 0
        allows = row["allows"] or 0
        total = intercepts + removes + allows

    with db_cursor() as cur:
        cur.execute(
            """SELECT name, enabled FROM threatintel_api ORDER BY id"""
        )
        sources = [dict(r) for r in cur.fetchall()]

    with db_cursor() as cur:
        cur.execute("SELECT value FROM system_config WHERE key='detection_enabled'")
        detection = cur.fetchone()["value"] == "1"

    return {"code": 0, "message": "ok", "data": {
        "detection_enabled": detection,
        "today_intercepts": intercepts,
        "today_removes": removes,
        "today_allows": allows,
        "today_total": total,
        # 统计口径来源（前端据此展示口径标记，避免误导）：
        #   query_stats → 全量精确（DNS 进程内存计数落库）
        #   filter_log  → 估算（allows 受采样低估，仅拦截/剔除可靠）
        "stats_source": "query_stats" if qs is not None else "filter_log",
        "threatintel_sources": sources,
    }}


@router.get("/status/trend")
def status_trend(days: int = 7, _: str = Depends(get_current_user)):
    """近 N 日拦截/剔除趋势（仪表盘趋势图与环比芯片用）。

    Task #166（口径修正迭代 26）：
    - 统计源优先 dns_query_stats（全量口径），无数据回退 filter_log
      （拦截/剔除可靠，allows 受采样低估）；
    - 时间窗口统一本地时区（filter_log.timestamp 存 localtime，
      旧实现 UTC 起点，UTC+8 环境窗口边界偏 8h）；
    - 今日为进行中的部分天，与昨日整天不可比——环比专用字段
      yesterday_* 由前端展示"较上一日"，只拿"已完成整天"对比，
      杜绝"上午看永远大降"的系统性误导（迭代 25 后首日新增）。
    """
    days = max(1, min(days, 90))
    with db_cursor() as cur:
        # 主口径：dns_query_stats（每日本地日期一行，全量计数）
        rows = cur.execute(
            """SELECT date, intercept, remove_ip, allow FROM dns_query_stats
               WHERE date >= date('now','localtime', ?)
               ORDER BY date""",
            (f"-{days - 1} days",),
        ).fetchall()
        items = [dict(r) for r in rows]
        have_stats = bool(items)

        if not have_stats:
            # 回退（升级过渡期 / 统计表尚未落任何行）：filter_log 聚合
            rows = cur.execute(
                """SELECT date(timestamp) AS date,
                     SUM(CASE WHEN action='intercept' THEN 1 ELSE 0 END) AS intercept,
                     SUM(CASE WHEN action='remove_ip'  THEN 1 ELSE 0 END) AS remove_ip,
                     SUM(CASE WHEN action='allow'     THEN 1 ELSE 0 END) AS allow
                   FROM filter_log
                   WHERE timestamp >= datetime('now','localtime', ?)
                   GROUP BY date(timestamp) ORDER BY date""",
                (f"-{days - 1} days",),
            ).fetchall()
            items = [dict(r) for r in rows]

        # 环比基准（较上一日）：今日 vs 昨日整天。今日是进行中部分天，
        # 直接对比必虚降——改为"今日当前值 vs 昨日同时刻"更可比，但
        # filter_log 无分时基线，这里取数"昨日全天"供前端标注口径；
        # 同时提供 today_elapsed_hours 供前端按时间折算（如显示
        # "截至今日 09:23"）。
        yesterday = None
        today = None
        _today_s = date.today().isoformat()
        if have_stats:
            cur.execute(
                "SELECT date, intercept, remove_ip, allow FROM dns_query_stats "
                "WHERE date IN (date('now','localtime'), date('now','localtime','-1 day'))"
            )
            for r in cur.fetchall():
                d = dict(r)
                if d["date"] == _today_s:
                    today = d
                else:
                    yesterday = d
        else:
            cur.execute(
                """SELECT date(timestamp) AS date,
                     SUM(CASE WHEN action='intercept' THEN 1 ELSE 0 END) AS intercept,
                     SUM(CASE WHEN action='remove_ip'  THEN 1 ELSE 0 END) AS remove_ip,
                     SUM(CASE WHEN action='allow'     THEN 1 ELSE 0 END) AS allow
                   FROM filter_log
                   WHERE date(timestamp) IN (date('now','localtime'), date('now','localtime','-1 day'))
                   GROUP BY date(timestamp)"""
            )
            for r in cur.fetchall():
                d = dict(r)
                if d["date"] == _today_s:
                    today = d
                else:
                    yesterday = d

        # 已完成整天的列表（今日进行中，不入环比）
        full_days = [it["date"] for it in items if it["date"] < _today_s]
        cur_hour = time.localtime()
        elapsed = cur_hour.tm_hour + cur_hour.tm_min / 60.0

    return {"code": 0, "message": "ok", "data": {
        "days": days,
        "items": items,
        "stats_source": "query_stats" if have_stats else "filter_log",
        # 环比专用：已完成昨天（今日进行中，其自身不入环比）
        "today": today,
        "yesterday": yesterday,
        "today_elapsed_hours": round(elapsed, 2),
        "full_days": full_days,
    }}





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
    # 时间窗口统一本地时区（filter_log.timestamp 存 localtime；
    # 旧实现 UTC 起点，UTC+8 环境窗口边界偏 8h——迭代 26 修正）
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
               WHERE timestamp >= datetime('now','localtime', ?)""",
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
               WHERE timestamp >= datetime('now','localtime', ?)
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


@router.get("/ip-cache/stats")
def ip_cache_stats(_: str = Depends(get_current_user)):
    """IP 检测结论缓存状态：条目数/容量/命中数/命中率（与域名缓存同构）。

    压测观测与运维巡检用；进程内累计，重启归零。
    """
    import ip_cache
    return {"code": 0, "message": "ok", "data": ip_cache.stats()}


@router.get("/log-writer/stats")
def log_writer_stats(_: str = Depends(get_current_user)):
    """异步日志写入状态：入队/落库/丢弃计数、当前队列深度。

    dropped>0 或 queue_size 持续增长说明写入跟不上（需调大批量/缩短
    间隔，或检查 DB 磁盘 IO）；运维巡检与压测观测用。
    """
    import log_writer
    return {"code": 0, "message": "ok", "data": log_writer.stats()}


@router.get("/log-retention/stats")
def log_retention_stats(_: str = Depends(get_current_user)):
    """日志保留期清理状态：最近/累计删除行数、执行轮数（运维巡检用）。

    last_run_at 为 0 说明清理线程尚未跑过首轮；total_deleted 长期为 0
    且库体积持续增长时检查 log_retention_days 是否被调得过大。
    """
    import log_retention
    return {"code": 0, "message": "ok", "data": log_retention.stats()}


@router.get("/circuit-breaker/stats")
def circuit_breaker_stats(_: str = Depends(get_current_user)):
    """熔断降级状态：各情报源熔断器 + 路径级降级 + 上游解析熔断（Task #159）。"""
    import circuit_breaker
    return {"code": 0, "message": "ok", "data": {
        "sources": circuit_breaker.source_states(),
        "degrade": circuit_breaker.degrade_state(),
        "upstream": circuit_breaker.upstream_state(),
    }}


@router.get("/queue-stats")
def dns_queue_stats(_: str = Depends(get_current_user)):
    """DNS 检测线程池队列状态（Task #160：executor 队列深度观测）。

    pending/inflight/max_pending 反映检测主池是否供不应求（2026-09-03
    事故形态：worker 全忙 + 队列无限积压 → 事件循环健康但全网无应答）。
    注意：Web 与 DNS 为双进程部署时，此接口读取的是 **Web 进程自身**
    的执行器计数（恒 0）——生产排障请以 DNS 进程 journalctl 告警与
    py-spy dump 为准；本端点主要服务单进程形态与本地验证。
    """
    import queue_stats
    return {"code": 0, "message": "ok", "data": queue_stats.stats()}


@router.post("/circuit-breaker/reset")
def circuit_breaker_reset(user: str = Depends(get_current_user)):
    """手动复位全部熔断器与降级状态（源恢复后强制清除用）。"""
    import circuit_breaker
    circuit_breaker.reset_all()
    write_audit(user, "circuit_breaker_reset", {})
    return {"code": 0, "message": "ok", "data": {}}


@router.post("/detection/toggle")
def toggle_detection(body: dict, user: str = Depends(get_current_user)):
    """切换检测总开关；关闭时全部请求直接放行（操作留痕）。"""
    enabled = bool(body.get("enabled"))
    set_config("detection_enabled", str(int(enabled)))
    write_audit(user, "detection_toggle", {"enabled": enabled})
    return {"code": 0, "message": "ok",
            "data": {"detection_enabled": enabled}}


class ProxyTestBody(BaseModel):
    proxy: str = ""          # 待测代理地址；空 = 用当前已保存的 CONFIG.http_proxy


@router.post("/proxy/test")
def test_proxy(body: ProxyTestBody, _: str = Depends(get_current_user)):
    """测试情报出站代理连通性：经代理访问一个轻量 HTTPS 端点。

    - body.proxy 传入时按传入值临时构建客户端（保存前预检）；
      不传/为空则复用当前 CONFIG.http_proxy（保存后验证）；
    - 目标端点用域名（双栈），能同时验证代理的 DNS 解析与转发能力；
    - 成功返回状态码与耗时；失败返回具体异常摘要（前端 toast 展示）。
    """
    import time

    import httpx

    from app import http_client as hc

    proxy = (body.proxy or "").strip()
    if not proxy:
        proxy = hc._current_proxy()
    if not proxy:
        raise HTTPException(status_code=400,
                            detail="未提供代理地址，且系统当前未配置代理")
    err = None
    try:
        proxy = _validate_proxy(proxy)
    except HTTPException as e:
        raise HTTPException(status_code=400,
                            detail=f"代理地址格式无效：{e.detail}")
    t0 = time.monotonic()
    try:
        # 独立构建临时 Client（不影响线程缓存里的正式客户端）
        with httpx.Client(proxy=proxy, timeout=httpx.Timeout(10, connect=5),
                          follow_redirects=True) as client:
            resp = client.get("https://www.baidu.com",
                              headers={"User-Agent": "dns-security-filter/1.0"})
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            ok = resp.status_code == 200
            return {"code": 0, "message": "ok", "data": {
                "proxy": proxy,
                "reachable": ok,
                "status_code": resp.status_code,
                "elapsed_ms": elapsed_ms,
                "detail": "代理连通" if ok else f"经代理访问返回 {resp.status_code}",
            }}
    except HTTPException:
        raise
    except Exception as e:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return {"code": 0, "message": "ok", "data": {
            "proxy": proxy,
            "reachable": False,
            "status_code": 0,
            "elapsed_ms": elapsed_ms,
            "detail": f"代理不可达：{type(e).__name__}: {e}",
        }}


@router.get("/proxy/status")
def proxy_status(_: str = Depends(get_current_user)):
    """当前情报出站代理状态（配置页展示用）。"""
    from app import http_client
    return {"code": 0, "message": "ok",
            "data": http_client.proxy_status()}
