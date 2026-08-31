"""威胁情报源配置 + 融合策略（PRD 7.2 威胁情报源）。

内置开源情报源（spamhaus_zen/dbl、dronebl、spfbl、urlhaus）由 seed
预置（is_builtin=1，免 Key 开箱即用），管理员在界面启停；内置源禁止删除。
"""

import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from adapters import ADAPTER_REGISTRY, build_adapter
import domain_cache
import ip_cache
from app.auth import get_current_user
from app.audit import write_audit
from app.crypto import encrypt_key, decrypt_key
from app.db import db_cursor
from app.runtime import set_config

router = APIRouter(prefix="/api/threatintel", tags=["threatintel"])

VALID_STRATEGIES = {"any", "majority", "all"}
BUILTIN_DESCRIPTIONS = {
    "spamhaus_zen": "Spamhaus ZEN IP 信誉黑名单（免 Key）",
    "spamhaus_dbl": "Spamhaus DBL 域名黑名单（免 Key）",
    "dronebl": "DroneBL 僵尸网络/滥用 IP 黑名单（免 Key）",
    "spfbl": "SPFBL 综合黑名单（免 Key）",
    "urlhaus": "URLhaus 恶意 URL 分发库（需 Auth-Key，auth.abuse.ch 免费申请）",
}


class FusionBody(BaseModel):
    strategy: str  # any / majority / all


@router.put("/fusion-strategy")
def set_fusion_strategy(body: FusionBody, user: str = Depends(get_current_user)):
    """注意：本路由必须注册在 PUT /{item_id} 之前，否则路径会被
    item_id 参数捕获（int 解析失败返回 422）。"""
    if body.strategy not in VALID_STRATEGIES:
        raise HTTPException(status_code=400,
                            detail="strategy 必须为 any/majority/all")
    with db_cursor() as cur:
        cur.execute("SELECT value FROM system_config WHERE key='fusion_strategy'")
        old = cur.fetchone()["value"]
    set_config("fusion_strategy", body.strategy)
    domain_cache.threatintel_invalidate(); ip_cache.threatintel_invalidate()   # 结论缓存依赖融合策略，切换即全清
    write_audit(user, "fusion_strategy_change",
                {"from": old, "to": body.strategy})
    return {"code": 0, "message": "ok",
            "data": {"strategy": body.strategy}}


class ThreatIntelBody(BaseModel):
    name: str
    adapter_type: str = "http"   # http / dnsbl
    base_url: str = ""
    api_key: str = ""
    enabled: bool = False
    timeout_ms: int = 2000
    config: str = ""             # JSON 扩展配置
    description: str = ""


def _mask_key(api_key: str) -> str:
    """密钥脱敏：仅返回后 4 位（前端显示用）。"""
    if not api_key:
        return ""
    return "●●●●●●" + api_key[-4:]


def _decorate(row: dict) -> dict:
    """补充适配器元信息（脱敏、注册、能力、内置标签）。

    api_key 先解密再脱敏：历史明文与新密文展示口径一致（尾 4 位）。
    """
    name = row["name"]
    row["api_key_masked"] = _mask_key(decrypt_key(row.pop("api_key", "")))
    row["adapter_registered"] = name in ADAPTER_REGISTRY
    cls = ADAPTER_REGISTRY.get(name)
    row["supports_domain"] = cls.supports_domain if cls else False
    row["supports_ip"] = cls.supports_ip if cls else False
    row["is_builtin"] = bool(row.get("is_builtin", 0))
    row["adapter_type"] = row.get("adapter_type") or \
        (cls.adapter_type if cls else "http")
    return row


@router.get("")
def list_threatintel(_: str = Depends(get_current_user)):
    """全部情报源配置（api_key 脱敏）+ 适配器注册情况。"""
    with db_cursor() as cur:
        cur.execute("SELECT * FROM threatintel_api ORDER BY id")
        rows = [_decorate(dict(r)) for r in cur.fetchall()]
    return {"code": 0, "message": "ok", "data": {
        "items": rows,
        "registered_adapters": sorted(ADAPTER_REGISTRY.keys()),
    }}


@router.post("")
def create_threatintel(body: ThreatIntelBody, user: str = Depends(get_current_user)):
    name = body.name.strip().lower()
    if name not in ADAPTER_REGISTRY:
        raise HTTPException(status_code=400,
                            detail=f"适配器未注册，可选：{sorted(ADAPTER_REGISTRY)}")
    if body.adapter_type not in ("http", "dnsbl"):
        raise HTTPException(status_code=400, detail="adapter_type 须为 http/dnsbl")
    if body.timeout_ms < 100 or body.timeout_ms > 30000:
        raise HTTPException(status_code=400, detail="timeout_ms 须在 100~30000 之间")
    with db_cursor() as cur:
        cur.execute("SELECT 1 FROM threatintel_api WHERE name=?", (name,))
        if cur.fetchone():
            raise HTTPException(status_code=409, detail=f"情报源 {name} 已存在")
        cur.execute(
            """INSERT INTO threatintel_api
               (name, adapter_type, base_url, api_key, enabled, timeout_ms,
                config, description)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, body.adapter_type, body.base_url,
             encrypt_key(body.api_key),      # 落库加密（P1-2）
             int(body.enabled), body.timeout_ms, body.config,
             body.description or BUILTIN_DESCRIPTIONS.get(name, "")),
        )
        item_id = cur.lastrowid
    write_audit(user, "threatintel_create", {
        "id": item_id, "name": name, "adapter_type": body.adapter_type,
        "base_url": body.base_url, "enabled": body.enabled,
        "timeout_ms": body.timeout_ms,
    })
    domain_cache.threatintel_invalidate(); ip_cache.threatintel_invalidate()   # 情报源集合变化，清结论缓存
    return {"code": 0, "message": "ok", "data": {"id": item_id}}


@router.put("/{item_id}")
def update_threatintel(item_id: int, body: ThreatIntelBody,
                       user: str = Depends(get_current_user)):
    """更新配置。api_key 传空或传脱敏值（含 ●）时保留原密钥。"""
    with db_cursor() as cur:
        cur.execute("SELECT * FROM threatintel_api WHERE id=?", (item_id,))
        row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="情报源不存在")

    name = body.name.strip().lower()
    if name != row["name"]:
        if name not in ADAPTER_REGISTRY:
            raise HTTPException(status_code=400, detail="适配器未注册")
        if name != row["name"]:
            with db_cursor() as cur:
                cur.execute("SELECT 1 FROM threatintel_api WHERE name=?", (name,))
                if cur.fetchone():
                    raise HTTPException(status_code=409, detail=f"情报源 {name} 已存在")

    keep_key = not body.api_key or "●" in body.api_key
    # 保留原密钥时维持密文原样（不经历解密再加密的密文轮换）；
    # 传入新明文时加密落库（P1-2）
    api_key = row["api_key"] if keep_key else encrypt_key(body.api_key)
    changes = {}
    for k, old, new in (
        ("base_url", row["base_url"], body.base_url),
        ("timeout_ms", row["timeout_ms"], body.timeout_ms),
        ("enabled", bool(row["enabled"]), body.enabled),
        ("config", row["config"] or "", body.config),
        ("description", row["description"] or "", body.description),
    ):
        if old != new:
            changes[k] = {"from": old, "to": new}

    with db_cursor() as cur:
        cur.execute(
            """UPDATE threatintel_api
               SET name=?, base_url=?, api_key=?, enabled=?, timeout_ms=?,
                   config=?, description=?,
                   updated_at=datetime('now','localtime')
               WHERE id=?""",
            (name, body.base_url, api_key, int(body.enabled),
             body.timeout_ms, body.config, body.description, item_id),
        )
    if changes:
        write_audit(user, "threatintel_update", {"id": item_id, **changes})
        domain_cache.threatintel_invalidate(); ip_cache.threatintel_invalidate()   # 启停/参数变化影响结论，清缓存
    return {"code": 0, "message": "ok", "data": {"id": item_id}}


@router.delete("/{item_id}")
def delete_threatintel(item_id: int, user: str = Depends(get_current_user)):
    with db_cursor() as cur:
        cur.execute("SELECT name, is_builtin FROM threatintel_api WHERE id=?",
                    (item_id,))
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="情报源不存在")
        if row["is_builtin"]:
            raise HTTPException(status_code=403,
                                detail="内置开源情报源不可删除，停用即可")
        cur.execute("DELETE FROM threatintel_api WHERE id=?", (item_id,))
    write_audit(user, "threatintel_delete", {"id": item_id, "name": row["name"]})
    domain_cache.threatintel_invalidate(); ip_cache.threatintel_invalidate()   # 情报源集合变化，清结论缓存
    return {"code": 0, "message": "ok", "data": {}}


@router.post("/{item_id}/test")
def test_threatintel(item_id: int, user: str = Depends(get_current_user)):
    """连通性测试：以 example.com 调用该源 query_domain/query_ip，
    返回 {ok, detail, latency_ms}。ok=False 表示请求失败（超时/网络/鉴权）。
    """
    with db_cursor() as cur:
        cur.execute("SELECT * FROM threatintel_api WHERE id=?", (item_id,))
        row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="情报源不存在")

    adapter = build_adapter(row["name"], row["base_url"],
                            decrypt_key(row["api_key"]),   # 解密后传入（P1-2）
                            row["timeout_ms"],
                            row["config"] or "")
    if adapter is None:
        return {"code": 0, "message": "ok",
                "data": {"ok": False, "detail": "适配器未注册", "latency_ms": 0}}

    start = time.monotonic()
    result = None
    if adapter.supports_domain:
        result = adapter.query_domain("example.com")
    elif adapter.supports_ip:
        result = adapter.query_ip("8.8.8.8")
    latency_ms = int((time.monotonic() - start) * 1000)

    if result is None:
        # 优先展示适配器记录的失败原因（如 URLhaus 缺 Auth-Key），便于诊断
        detail = getattr(adapter, "last_error", "") or \
            "请求失败（超时/网络/鉴权错误），详见平台日志"
        return {"code": 0, "message": "ok",
                "data": {"ok": False, "detail": detail,
                         "latency_ms": latency_ms}}
    return {"code": 0, "message": "ok",
            "data": {"ok": True, "detail": result.detail, "latency_ms": latency_ms}}
