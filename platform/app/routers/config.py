"""系统配置读写 + 平台状态 + 检测总开关（PRD 7.2 系统配置/状态）。"""

from fastapi import APIRouter, Depends

from app.auth import get_current_user
from app.db import db_cursor, get_system_config

router = APIRouter(prefix="/api", tags=["config"])


@router.get("/config")
def read_config(_: str = Depends(get_current_user)):
    # TODO(AI): 读取 system_config 全部键值返回（供 Web 界面展示）
    return {"code": 0, "message": "ok", "data": {}}


@router.put("/config")
def update_config(body: dict, user: str = Depends(get_current_user)):
    # TODO(AI): 逐键更新 system_config，写 audit_log(config_update)
    return {"code": 0, "message": "ok", "data": {}}


@router.get("/status")
def platform_status(_: str = Depends(get_current_user)):
    """平台运行状态：检测开关、今日拦截/放行计数、情报源状态。"""
    # TODO(AI): 今日拦截数 = 今日 filter_log 条数（action=intercept）
    return {"code": 0, "message": "ok",
            "data": {
                "detection_enabled": True,
                "today_intercepts": 0,
                "today_allows": 0,
                "threatintel_sources": [],
            }}


@router.post("/detection/toggle")
def toggle_detection(body: dict, user: str = Depends(get_current_user)):
    """切换检测总开关；关闭时全部请求直接放行（操作留痕）。"""
    # TODO(AI): 更新 system_config.detection_enabled，
    #   写 audit_log(detection_toggle, detail={"enabled": bool})
    return {"code": 0, "message": "ok", "data": {}}
