"""离线大名单管理（hagezi / StevenBlack 恶意域名列表）。

与在线威胁情报源互补：一次导入本地 SQLite，离线匹配、零 Key、零延迟，
检测主流程在本地黑名单之后、在线情报源之前命中即拦截。

导入为后台任务：POST /import 立即返回，前端轮询 /import/status 展示进度
（下载 → 解析 → 入库三阶段，进度存进程内存）。

接口：
  GET    /api/threatlist/sources   内置来源 + 各来源条数/更新时间/启用状态/下次更新调度
  GET    /api/threatlist/domains   ?source=&keyword=&enabled=&page=&size= 分页查看某来源具体条目
  POST   /api/threatlist/import    {source?, url?, enabled?} 后台下载并整源替换导入
  GET    /api/threatlist/import/status ?source=xxx 查询导入任务进度
  GET    /api/threatlist/query     ?value=域名|IP → 命中详情（大名单 + 手工名单）
  PUT    /api/threatlist/source    {source, enabled} 整体启停
  DELETE /api/threatlist/source    ?source=xxx 清空该来源
"""

import threading
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app import threat_list
from app.auto_update import interval_seconds
from app.audit import write_audit
from app.auth import get_current_user
from app.db import db_cursor, get_enabled_list
from config import CONFIG
from detectors import _match_domain, _match_ip

router = APIRouter(prefix="/api/threatlist", tags=["threatlist"])

CUSTOM_SOURCE = "custom"


class ImportBody(BaseModel):
    source: str = ""       # 内置来源 key（hagezi_ti/hagezi_ult/stevenblack）
    url: str = ""          # 自定义导入时填；内置来源可省略
    enabled: bool = True   # 导入后默认启用（整体开关仍可随时切换）


class SourceEnableBody(BaseModel):
    source: str
    enabled: bool


def _resolve_source(body: ImportBody) -> tuple[str, str, str]:
    """返回 (source_key, url, format)。支持内置 key 或自定义 url。"""
    if body.url.strip():
        return CUSTOM_SOURCE, body.url.strip(), "auto"
    key = body.source.strip().lower()
    meta = threat_list.source_stats()
    if key not in meta:
        raise HTTPException(
            status_code=400,
            detail=f"未知来源 {key}，内置可选：{sorted(meta)}；或提供自定义 url")
    return key, meta[key]["url"], meta[key].get("format", "auto")


def _run_import_task(source: str, url: str, enabled: bool,
                     user: str, fmt: str = "auto") -> None:
    """后台执行完整导入流程，逐步更新任务进度。

    任务对象由 POST /import 在请求线程中 begin_import 创建并置 running，
    这里直接取回引用（不再 begin，避免并发保护返回 None）。
    fmt：解析格式（内置源元数据携带，如 C2IntelFeeds 的 csv）。
    """
    t = threat_list.import_progress(source)
    try:
        t.update(stage="download", message="下载中…")
        text = threat_list.download(url, timeout_s=90, progress=t)
        t.update(stage="parse", message="解析中…")
        n = threat_list.import_source(source, text, enabled=enabled,
                                      progress=t, fmt=fmt)
        if n == 0:
            raise ValueError(
                "列表解析后无有效域名（格式不支持或内容为空）")
        t.update(status="done", stage="finish", total=n,
                 message=f"导入完成 {n} 条",
                 finished_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        write_audit(user, "threatlist_import",
                    {"source": source, "url": url, "imported": n,
                     "enabled": enabled})
        threat_list.logger.info("后台导入 %s 完成：%d 条", source, n)
    except Exception as e:      # 下载失败 / 解析为空 / 入库异常统一收敛
        t.update(status="error", error=str(e), message="导入失败",
                 finished_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        threat_list.logger.error("后台导入 %s 失败：%s", source, e)


@router.get("/sources")
def list_sources(_: str = Depends(get_current_user)):
    """内置来源元数据 + 各来源当前统计（条数/启用数/更新时间）
    + 自动更新调度信息（实际周期 / 下次更新时间 / 是否到期 / 开关状态）。"""
    auto_on = bool(getattr(CONFIG, "threatlist_auto_update", False))
    sched = threat_list.next_update_schedule(
        interval_seconds() if auto_on else None)
    items = []
    for s in threat_list.source_stats().values():
        s.update(sched.get(s["key"], {}))
        s["auto_update_on"] = auto_on
        items.append(s)
    return {"code": 0, "message": "ok", "data": {"items": items}}


@router.post("/import")
def import_list(body: ImportBody, user: str = Depends(get_current_user)):
    """后台下载并整源替换导入（重复导入即增量更新）。

    立即返回 task=started；真实结果通过 /import/status 轮询获取，
    同来源已有进行中任务时返回 409。
    """
    source, url, fmt = _resolve_source(body)
    t = threat_list.begin_import(source)
    if t is None:
        raise HTTPException(status_code=409,
                            detail=f"来源 {source} 正在导入中，请等待完成后再试")
    threading.Thread(target=_run_import_task,
                     args=(source, url, body.enabled, user, fmt),
                     daemon=True, name=f"tl-import-{source}").start()
    return {"code": 0, "message": "ok",
            "data": {"task": "started", "source": source}}


@router.get("/import/status")
def import_status(source: str | None = Query(None),
                  _: str = Depends(get_current_user)):
    """查询导入任务进度（download/parse/insert 三阶段）。

    source 省略时返回本进程全部非 idle 任务列表，
    供前端一次轮询多个并发任务、刷新页面后恢复进行中任务的进度展示。
    """
    if source:
        data = threat_list.import_progress(source)
    else:
        data = [t for t in threat_list.import_progress()
                if t["status"] != "idle"]
    return {"code": 0, "message": "ok", "data": data}


@router.get("/domains")
def list_domains(source: str = Query(..., min_length=1),
                 keyword: str = Query("", description="按条目子串模糊过滤"),
                 enabled: bool | None = Query(
                     None, description="留空全部；true/false 按状态过滤"),
                 page: int = Query(1, ge=1),
                 size: int = Query(50, ge=1, le=500),
                 _: str = Depends(get_current_user)):
    """分页查看某来源的具体条目（域名 / IP），供前端"查看条目"使用。"""
    return {"code": 0, "message": "ok", "data": threat_list.list_entries(
        source, keyword=keyword, enabled=enabled, page=page, size=size)}


@router.get("/query")
def query_list(value: str = Query(..., min_length=1),
               _: str = Depends(get_current_user)):
    """查域名 / IP 是否命中大名单与手工黑白名单（排查用）。"""
    v = value.strip().lower().rstrip(".")
    if not v:
        raise HTTPException(status_code=400, detail="value 不能为空")

    tl = threat_list.find_domain(v) or threat_list.find_ip(v)
    manual_bl = None
    for rule in get_enabled_list("blacklist", "domain"):
        if _match_domain(v, [rule]):
            manual_bl = rule
            break
    if manual_bl is None:
        for rule in get_enabled_list("blacklist", "ip"):
            if _match_ip(v, [rule]):
                manual_bl = rule
                break
    manual_wl = None
    for rule in get_enabled_list("whitelist", "domain"):
        if _match_domain(v, [rule]):
            manual_wl = rule
            break

    return {"code": 0, "message": "ok", "data": {
        "value": v,
        "threat_list": {
            "matched": tl is not None,
            "source": tl[0] if tl else None,
            "entry": tl[1] if tl else None,
        },
        "manual_blacklist": manual_bl,
        "manual_whitelist": manual_wl,
    }}


@router.put("/source")
def enable_source(body: SourceEnableBody, user: str = Depends(get_current_user)):
    """整体启停某来源（条目保留，停用即不参与匹配）。"""
    with db_cursor() as cur:
        cur.execute("SELECT COUNT(*) AS c FROM threat_list WHERE source=?",
                    (body.source,))
        if cur.fetchone()["c"] == 0:
            raise HTTPException(status_code=404,
                                detail=f"来源 {body.source} 无数据")
    n = threat_list.enable_source(body.source, body.enabled)
    write_audit(user, "threatlist_enable",
                {"source": body.source, "enabled": body.enabled,
                 "rows": n})
    return {"code": 0, "message": "ok", "data": {"affected": n}}


@router.delete("/source")
def delete_source(source: str = Query(...),
                  user: str = Depends(get_current_user)):
    """清空某来源数据（内置来源可重新导入恢复）。"""
    n = threat_list.delete_source(source)
    write_audit(user, "threatlist_delete", {"source": source, "rows": n})
    return {"code": 0, "message": "ok", "data": {"deleted": n}}
