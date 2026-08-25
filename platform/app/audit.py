"""操作审计写入辅助（audit_log 表，PRD 6.6）。

所有敏感操作（名单变更、检测开关、情报源启停、配置修改）统一经
write_audit 落库，Web 审计页面可查。
"""

import json

from app.db import db_cursor


def write_audit(operator: str, action: str, detail: dict) -> None:
    """写一条审计记录。detail 为可 JSON 序列化的变更内容。"""
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO audit_log (operator, action, detail) VALUES (?, ?, ?)",
            (operator, action, json.dumps(detail, ensure_ascii=False)),
        )


# ==================== 审计详情可读化 ====================

_ACTION_LABELS = {
    "list_create": "新增名单条目",
    "list_update": "修改名单条目",
    "list_delete": "删除名单条目",
    "list_import": "批量导入名单",
    "threatintel_create": "新增情报源",
    "threatintel_update": "修改情报源",
    "threatintel_delete": "删除情报源",
    "threatlist_import": "导入离线大名单",
    "threatlist_enable": "启停离线大名单",
    "threatlist_delete": "清空离线大名单",
    "fusion_strategy_change": "切换融合策略",
    "detection_toggle": "切换检测开关",
    "config_update": "修改系统配置",
}

_LIST_TYPE_LABELS = {"blacklist": "黑名单", "whitelist": "白名单"}
_TARGET_LABELS = {"domain": "域名", "ip": "IP"}
_FUSION_LABELS = {
    "any": "任意命中即拦截",
    "majority": "多数命中即拦截",
    "all": "全部命中才拦截",
}
_CONFIG_LABELS = {
    "alert_ip": "告警IP", "alert_ttl": "告警TTL", "upstream_dns": "上游DNS",
    "fusion_strategy": "融合策略", "log_retention_days": "日志保留天数",
    "allow_log_enabled": "放行日志", "detection_enabled": "检测总开关",
    "api_timeout_ms": "情报源超时", "threatlist_auto_update": "大名单自动更新",
    "threatlist_auto_interval_hours": "大名单自动更新间隔",
    "admin_initial_password": "管理员初始密码",
}
_FIELD_LABELS = {
    "enabled": "启用状态", "value": "匹配值", "remark": "备注",
    "list_type": "名单类型", "target": "匹配目标",
    "base_url": "接口地址", "timeout_ms": "超时",
    "config": "配置", "description": "描述", "name": "名称",
    "api_key": "API密钥",
}


def action_label(action: str) -> str:
    """动作的中文标签（供前端展示）。"""
    return _ACTION_LABELS.get(action, action)


def _fmt_bool(v):
    if v is True or v == 1 or v == "1":
        return "启用"
    if v is False or v == 0 or v == "0":
        return "停用"
    return str(v)


def _fmt_val(field, v):
    if field == "enabled":
        return _fmt_bool(v)
    if field == "fusion_strategy":
        return _FUSION_LABELS.get(str(v), str(v))
    if field == "list_type":
        return _LIST_TYPE_LABELS.get(str(v), str(v))
    if field == "target":
        return _TARGET_LABELS.get(str(v), str(v))
    if v is None:
        return "空"
    if isinstance(v, bool):
        return "开" if v else "关"
    return str(v)


def _fmt_changes(changes: dict) -> str:
    """changes: {field: {from, to}} 或 {field: value} → '字段：旧→新；...'"""
    parts = []
    for k, ch in changes.items():
        label = _FIELD_LABELS.get(k, k)
        if isinstance(ch, dict) and ("from" in ch or "to" in ch):
            parts.append(
                f"{label}：{_fmt_val(k, ch.get('from'))} → {_fmt_val(k, ch.get('to'))}"
            )
        else:
            parts.append(f"{label}：{_fmt_val(k, ch)}")
    return "；".join(parts)


def humanize(action: str, detail: dict, list_map: dict | None = None,
             ti_map: dict | None = None) -> str:
    """把审计 detail 翻译为中文可读摘要。

    list_map / ti_map: 批量预查的 id→条目信息映射，用于补全名单值与情报源名。
    解析失败或未知 action 时容错返回原始 JSON。
    """
    list_map = list_map or {}
    ti_map = ti_map or {}
    label = _ACTION_LABELS.get(action, action)
    try:
        if action in ("list_create", "list_update", "list_delete"):
            item_id = detail.get("id")
            info = list_map.get(item_id, {})
            val = detail.get("value") or info.get("value") or f"#{item_id}"
            lt = detail.get("list_type") or info.get("list_type") or ""
            tg = detail.get("target") or info.get("target") or ""
            prefix = ""
            if lt or tg:
                prefix = f"[{_LIST_TYPE_LABELS.get(lt, lt)}·{_TARGET_LABELS.get(tg, tg)}] "
            desc = f"{prefix}{val}（id={item_id}）"
            if action == "list_update":
                changes = {k: v for k, v in detail.items() if k != "id"}
                chg = _fmt_changes(changes)
                return f"{label}：{desc} — {chg}" if chg else f"{label}：{desc}"
            return f"{label}：{desc}"

        if action == "list_import":
            imp = detail.get("imported", 0)
            skp = detail.get("skipped", 0)
            return f"{label}：成功 {imp} 条，跳过 {skp} 条"

        if action in ("threatintel_create", "threatintel_update", "threatintel_delete"):
            item_id = detail.get("id")
            info = ti_map.get(item_id, {})
            name = detail.get("name") or info.get("name") or f"#{item_id}"
            atype = detail.get("adapter_type") or info.get("adapter_type") or ""
            if action == "threatintel_create":
                tp = f"，类型 {atype}" if atype else ""
                return f"{label}：{name}（id={item_id}{tp}）"
            if action == "threatintel_delete":
                return f"{label}：{name}（id={item_id}）"
            changes = {k: v for k, v in detail.items() if k != "id"}
            chg = _fmt_changes(changes)
            return f"{label}：{name}（id={item_id}）— {chg}" if chg \
                else f"{label}：{name}（id={item_id}）"

        if action == "threatlist_import":
            src = detail.get("source", "?")
            n = detail.get("imported", 0)
            en = detail.get("enabled")
            en_s = f"，{'已启用' if en else '未启用'}" if en is not None else ""
            return f"{label}「{src}」：{n} 条{en_s}"

        if action == "threatlist_enable":
            src = detail.get("source", "?")
            en = detail.get("enabled")
            rows = detail.get("rows", 0)
            en_s = "已启用" if en else "已停用"
            return f"{label}「{src}」：{en_s}（影响 {rows} 条）"

        if action == "threatlist_delete":
            src = detail.get("source", "?")
            rows = detail.get("rows", 0)
            return f"{label}「{src}」：{rows} 条"

        if action == "fusion_strategy_change":
            old = _FUSION_LABELS.get(str(detail.get("from", "")),
                                     str(detail.get("from", "")))
            new = _FUSION_LABELS.get(str(detail.get("to", "")),
                                     str(detail.get("to", "")))
            return f"{label}：{old} → {new}"

        if action == "detection_toggle":
            en = detail.get("enabled")
            return f"{label}：{'已开启' if en else '已关闭'}"

        if action == "config_update":
            parts = []
            for k, v in detail.items():
                fl = _CONFIG_LABELS.get(k, k)
                parts.append(f"{fl}改为「{_fmt_val(k, v)}」")
            return f"{label}：" + "；".join(parts) if parts else label

        return label
    except Exception:
        return json.dumps(detail, ensure_ascii=False)
