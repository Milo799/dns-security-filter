"""黑白名单 CRUD + 导入导出（PRD 7.2 黑白名单）。"""

from fastapi import APIRouter, Depends, Query

from app.auth import get_current_user
from app.db import db_cursor

router = APIRouter(prefix="/api/list", tags=["list"])


@router.get("")
def list_items(
    list_type: str | None = None,
    target: str | None = None,
    keyword: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    _: str = Depends(get_current_user),
):
    # TODO(AI): 分页查询 filter_list，支持 list_type/target/keyword 过滤
    return {"code": 0, "message": "ok",
            "data": {"total": 0, "items": []}}


@router.post("")
def create_item(body: dict, user: str = Depends(get_current_user)):
    # TODO(AI): 校验 list_type(blacklist/whitelist) + target(domain/ip) + value，
    #   插入 filter_list 并写 audit_log(list_create)
    return {"code": 0, "message": "ok", "data": {"id": 0}}


@router.put("/{item_id}")
def update_item(item_id: int, body: dict, user: str = Depends(get_current_user)):
    # TODO(AI): 更新 filter_list，写 audit_log(list_update)
    return {"code": 0, "message": "ok", "data": {}}


@router.delete("/{item_id}")
def delete_item(item_id: int, user: str = Depends(get_current_user)):
    # TODO(AI): 删除 filter_list，写 audit_log(list_delete)
    return {"code": 0, "message": "ok", "data": {}}


@router.post("/import")
def import_items(user: str = Depends(get_current_user)):
    # TODO(AI): CSV 批量导入（列：list_type,target,value,enabled,remark）
    return {"code": 0, "message": "ok", "data": {"imported": 0}}


@router.get("/export")
def export_items(user: str = Depends(get_current_user)):
    # TODO(AI): 导出 CSV（Content-Disposition: attachment）
    return {"code": 0, "message": "ok", "data": {}}
