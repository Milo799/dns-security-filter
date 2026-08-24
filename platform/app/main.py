"""FastAPI 应用入口：注册全部路由（PRD 7.2），启动时初始化数据库。

统一响应格式：{ "code": 0, "message": "ok", "data": {} }
"""

import logging

from fastapi import FastAPI

from app.routers import (
    auth, list, threatintel, logs, config as config_router, audit,
)
from app.db import get_conn
from seed import init_all

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="DNS 安全过滤平台", version="0.1.0")


@app.on_event("startup")
def on_startup():
    init_all()   # 建表 + 默认管理员 + 默认配置
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
