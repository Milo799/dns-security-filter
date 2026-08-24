"""FastAPI 应用入口：注册全部路由（PRD 7.2），启动时初始化数据库。

统一响应格式：{ "code": 0, "message": "ok", "data": {} }
"""

import logging
import os

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.routers import (
    auth, list, threatintel, logs, config as config_router, audit,
)
from app.db import get_conn
from app.runtime import sync_config_from_db
from seed import init_all

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="DNS 安全过滤平台", version="0.2.0")


@app.on_event("startup")
def on_startup():
    init_all()   # 建表 + 默认管理员 + 默认配置
    sync_config_from_db()   # DB 配置 → 内存 CONFIG（热配置基准）
    get_conn()


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

# 前端静态资源（web/index.html）：挂在 "/" 且注册在 API 路由之后，
# /api/* 优先匹配，其余路径由静态服务接管（访问 / 即控制台）。
_WEB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "web"))
if os.path.isdir(_WEB_DIR):
    app.mount("/", StaticFiles(directory=_WEB_DIR, html=True), name="web")
