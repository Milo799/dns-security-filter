"""威胁情报源配置 + 融合策略（PRD 7.2 威胁情报源）。"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.auth import get_current_user
from app.db import db_cursor

router = APIRouter(prefix="/api/threatintel", tags=["threatintel"])


class ThreatIntelBody(BaseModel):
    name: str
    base_url: str
    api_key: str = ""
    enabled: bool = False
    timeout_ms: int = 2000


@router.get("")
def list_threatintel(_: str = Depends(get_current_user)):
    # TODO(AI): 查询 threatintel_api 全部配置（api_key 脱敏返回）
    return {"code": 0, "message": "ok", "data": {"items": []}}


@router.post("")
def create_threatintel(body: ThreatIntelBody, user: str = Depends(get_current_user)):
    # TODO(AI): 注册适配器配置（api_key 加密存储），写 audit_log(threatintel_create)
    return {"code": 0, "message": "ok", "data": {"id": 0}}


@router.put("/{item_id}")
def update_threatintel(item_id: int, body: ThreatIntelBody,
                       user: str = Depends(get_current_user)):
    # TODO(AI): 更新配置（含启停），写 audit_log(threatintel_update)
    return {"code": 0, "message": "ok", "data": {}}


@router.delete("/{item_id}")
def delete_threatintel(item_id: int, user: str = Depends(get_current_user)):
    # TODO(AI): 删除配置，写 audit_log(threatintel_delete)
    return {"code": 0, "message": "ok", "data": {}}


@router.post("/{item_id}/test")
def test_threatintel(item_id: int, user: str = Depends(get_current_user)):
    """连通性测试：以 example.com 调用该源，返回是否可用。"""
    # TODO(AI): 用 item_id 对应适配器 query_domain("example.com")，
    #   返回 {ok: bool, detail: str}
    return {"code": 0, "message": "ok", "data": {"ok": False, "detail": ""}}


class FusionBody(BaseModel):
    strategy: str  # any / majority / all


@router.put("/fusion-strategy")
def set_fusion_strategy(body: FusionBody, user: str = Depends(get_current_user)):
    # TODO(AI): 校验 strategy 取值，写 system_config.fusion_strategy，
    #   写 audit_log(fusion_strategy_change)
    return {"code": 0, "message": "ok", "data": {}}
