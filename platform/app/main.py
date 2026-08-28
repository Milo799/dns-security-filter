"""FastAPI 应用入口：注册全部路由（PRD 7.2），启动时初始化数据库。

统一响应格式：{ "code": 0, "message": "ok", "data": {} }
"""

import asyncio
import logging
import os
import threading

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app import threat_list
from app.routers import (
    auth, list, threatintel, logs, config as config_router, audit,
    test as test_router, threatlist as threatlist_router,
)
from app.db import get_conn
from app.runtime import sync_config_from_db
from seed import init_all

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="DNS 安全过滤平台", version="0.3.0")


@app.on_event("startup")
async def on_startup():
    init_all()   # 建表 + 默认管理员 + 默认配置
    sync_config_from_db()   # DB 配置 → 内存 CONFIG（热配置基准）
    get_conn()
    # 异步日志写入线程（前置项5：SQLite 写入削峰）——
    # 检测线程只入队，后台线程批量 flush；atexit 兜底 flush 残留。
    import log_writer
    log_writer.start()
    # 后台预热离线大名单内存缓存（全量 enabled 条目约数秒）：
    # 避免服务重启后首条 DNS 查询懒加载阻塞；daemon 线程不拖慢启动。
    threading.Thread(target=threat_list.warm_cache, daemon=True,
                     name="tl-warmup").start()
    # 离线大名单自动更新后台任务（方案 A）
    from app.auto_update import auto_update_loop
    app.state.threatlist_auto_task = asyncio.create_task(auto_update_loop())


@app.on_event("shutdown")
async def on_shutdown():
    # 异步日志优雅关闭：flush 队列残留，防退出丢尾批
    import log_writer
    log_writer.stop(flush=True)
    task = getattr(app.state, "threatlist_auto_task", None)
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


@app.get("/api/health")
def health():
    return {"code": 0, "message": "ok", "data": {"status": "up"}}


# 注册路由
app.include_router(auth.router)
app.include_router(list.router)
app.include_router(threatintel.router)
app.include_router(logs.router)
app.include_router(config_router.router)
app.include_router(audit.router)
app.include_router(test_router.router)
app.include_router(threatlist_router.router)

# 前端静态资源（web/index.html）：挂在 "/" 且注册在 API 路由之后，
# /api/* 优先匹配，其余路径由静态服务接管（访问 / 即控制台）。
_WEB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "web"))
if os.path.isdir(_WEB_DIR):
    app.mount("/", StaticFiles(directory=_WEB_DIR, html=True), name="web")
