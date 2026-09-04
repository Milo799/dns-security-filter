"""黑白名单 CRUD + 导入导出（PRD 7.2 黑白名单）。

Task #176/#177（迭代 29/30）：域名层级防护——
  - 顶层通配（*.com / *.jp 等）只在**批量导入**时拒绝（批量无逐条
    确认环节，一条 *.com 混在几百行 CSV 里极易误入；手工单条添加
    属管理员明确意图——如把 *.jp 入黑名单做整域管控——放行但列表
    红标警示）；
  - 裸 * / *.（空后缀）无效语法全入口拒绝；
  - 列表支持按层级筛选（tld/registrable/subdomain）与通配符过滤，
    主域级通配标黄警示、顶层通配标红警示。
"""

import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel

from app.auth import get_current_user
from app.audit import write_audit
from app.db import db_cursor
from app.domain_level import classify_entry

router = APIRouter(prefix="/api/list", tags=["list"])

VALID_LIST_TYPES = {"blacklist", "whitelist"}
VALID_TARGETS = {"domain", "ip"}
VALID_LEVELS = {"tld", "registrable", "subdomain"}


class ListBody(BaseModel):
    list_type: str
    target: str
    value: str
    enabled: bool = True
    remark: str = ""


def _validate(list_type: str, target: str, value: str,
              strict_tld: bool = False) -> None:
    """条目校验（创建/更新/导入共用）。

    - 无效语法（裸 * / *. 空后缀等）：一律 400 拒绝；
    - 顶层通配（*.com / *.jp 等）：仅 strict_tld=True（CSV 批量导入）
      时拒绝——批量无逐条确认，*.com 混入即事故；手工添加是管理员
      明确意图（如 *.jp 整域管控），放行交由前端确认弹窗把关。
    """
    if list_type not in VALID_LIST_TYPES:
        raise HTTPException(status_code=400, detail="list_type 必须为 blacklist/whitelist")
    if target not in VALID_TARGETS:
        raise HTTPException(status_code=400, detail="target 必须为 domain/ip")
    value = (value or "").strip()
    if not value or len(value) > 255:
        raise HTTPException(status_code=400, detail="value 不能为空且不超过 255 字符")
    info = classify_entry(target, value)
    if info["risk"] == "blocked":
        # 无效语法（裸星号/空后缀）全入口拒绝
        if info["level"] != "tld" or not info["wildcard"]:
            raise HTTPException(status_code=400, detail=info["risk_note"])
        # 顶层通配：仅批量导入拒绝（Task #177）
        if strict_tld:
            raise HTTPException(status_code=400, detail=info["risk_note"])


@router.get("")
def list_items(
    list_type: str | None = None,
    target: str | None = None,
    keyword: str | None = None,
    domain_level: str | None = None,
    wildcard: bool | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    _: str = Depends(get_current_user),
):
    """分页查询 filter_list，支持类型/目标/关键字/域名层级过滤。

    Task #176 新增：
    - domain_level：tld（一级/公共后缀）/ registrable（主域/可注册域）/
      subdomain（子域）——仅对 target=domain 条目有意义；
    - wildcard：true/false 只看通配符/非通配符条目；
    - 每条目附加 level / wildcard / risk / risk_note（前端标黄警示
      主域级通配、排查存量过宽条目）。
    层级过滤在 Python 侧完成（分页前）：SQLite 无 PSL 语义，
      且人工名单量级（千~万）远低于需要 SQL 过滤的规模。
    """
    if domain_level is not None and domain_level not in VALID_LEVELS:
        raise HTTPException(
            status_code=400,
            detail="domain_level 必须为 tld/registrable/subdomain")

    where, params = [], []
    if list_type:
        where.append("list_type=?"); params.append(list_type)
    if target:
        where.append("target=?"); params.append(target)
    if keyword:
        where.append("value LIKE ?"); params.append(f"%{keyword}%")
    cond = ("WHERE " + " AND ".join(where)) if where else ""

    with db_cursor() as cur:
        cur.execute(f"SELECT COUNT(*) AS c FROM filter_list {cond}", params)
        total = cur.fetchone()["c"]
        # 层级/通配过滤需全量读（千~万级，无性能压力），分页在内存侧
        cur.execute(
            f"""SELECT * FROM filter_list {cond}
                ORDER BY updated_at DESC, id DESC""",
            params,
        )
        rows = [dict(r) for r in cur.fetchall()]

    enriched = []
    for r in rows:
        info = classify_entry(r["target"], r["value"])
        r["level"] = info["level"]
        r["wildcard"] = info["wildcard"]
        r["risk"] = info["risk"]
        r["risk_note"] = info["risk_note"]
        enriched.append(r)

    if domain_level is not None:
        enriched = [r for r in enriched
                    if r["target"] == "domain" and r["level"] == domain_level]
    if wildcard is not None:
        enriched = [r for r in enriched
                    if r["target"] == "domain"
                    and bool(r["wildcard"]) == bool(wildcard)]

    total = len(enriched)
    start = (page - 1) * size
    items = enriched[start:start + size]
    return {"code": 0, "message": "ok", "data": {"total": total, "items": items}}


@router.post("")
def create_item(body: ListBody, user: str = Depends(get_current_user)):
    _validate(body.list_type, body.target, body.value)
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO filter_list
               (list_type, target, value, enabled, remark, created_by)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (body.list_type, body.target, body.value.strip(),
             int(body.enabled), body.remark, user),
        )
        item_id = cur.lastrowid
    from app.db import invalidate_list_cache
    invalidate_list_cache()
    write_audit(user, "list_create", {
        "id": item_id, "list_type": body.list_type, "target": body.target,
        "value": body.value.strip(),
    })
    return {"code": 0, "message": "ok", "data": {"id": item_id}}


@router.put("/{item_id}")
def update_item(item_id: int, body: dict, user: str = Depends(get_current_user)):
    """部分更新：value / enabled / remark / list_type / target 至少一项。"""
    with db_cursor() as cur:
        cur.execute("SELECT * FROM filter_list WHERE id=?", (item_id,))
        row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="条目不存在")

    changes: dict = {}
    fields = {}
    for key in ("list_type", "target", "value", "remark"):
        if key in body and body[key] is not None and body[key] != row[key]:
            fields[key] = body[key]; changes[key] = {"from": row[key], "to": body[key]}
    if "enabled" in body and body["enabled"] is not None \
            and bool(body["enabled"]) != bool(row["enabled"]):
        fields["enabled"] = int(body["enabled"])
        changes["enabled"] = {"from": bool(row["enabled"]), "to": bool(body["enabled"])}

    new_type = fields.get("list_type", row["list_type"])
    new_target = fields.get("target", row["target"])
    new_value = fields.get("value", row["value"])
    _validate(new_type, new_target, new_value)

    if fields:
        sets = ", ".join(f"{k}=?" for k in fields)
        with db_cursor() as cur:
            cur.execute(
                f"""UPDATE filter_list SET {sets},
                     updated_at=datetime('now','localtime') WHERE id=?""",
                list(fields.values()) + [item_id],
            )
        write_audit(user, "list_update", {"id": item_id, **changes})
    from app.db import invalidate_list_cache
    invalidate_list_cache()
    return {"code": 0, "message": "ok", "data": {"id": item_id}}


@router.delete("/{item_id}")
def delete_item(item_id: int, user: str = Depends(get_current_user)):
    with db_cursor() as cur:
        cur.execute("SELECT value FROM filter_list WHERE id=?", (item_id,))
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="条目不存在")
        cur.execute("DELETE FROM filter_list WHERE id=?", (item_id,))
    from app.db import invalidate_list_cache
    invalidate_list_cache()
    write_audit(user, "list_delete", {"id": item_id, "value": row["value"]})
    return {"code": 0, "message": "ok", "data": {}}


@router.post("/import")
async def import_items(request: Request, user: str = Depends(get_current_user)):
    """CSV 批量导入。请求体为 CSV 文本，列：list_type,target,value,enabled,remark。
    首行可为表头（自动识别）。逐行校验，非法行跳过并汇总原因。
    自动消重：同一 (list_type, target, value) 视为重复（域名键不区分大小写）——
    ① 文件内部重复只保留首条；② 与库中已有条目重复的跳过；结果返回消重数量。
    跨名单冲突：导入的条目已存在于另一份名单（白↔黑）时不拦截导入，
    但返回 conflicts 明细（白名单命中优先放行，属安全提醒）。
    """
    raw = (await request.body()).decode("utf-8-sig", errors="replace")
    if not raw.strip():
        raise HTTPException(status_code=400, detail="导入内容为空")

    reader = csv.reader(io.StringIO(raw))
    rows = list(reader)
    if not rows:
        raise HTTPException(status_code=400, detail="导入内容为空")

    header = [c.strip().lower() for c in rows[0]]
    if "list_type" in header:  # 首行是表头则跳过
        rows = rows[1:]

    def _key(list_type: str, target: str, value: str) -> tuple:
        """消重键：域名不区分大小写（*.Bad.COM 与 *.bad.com 同条）。"""
        return (list_type, target, value.strip().lower())

    # ---- 阶段一：解析 + 校验 + 文件内部消重（保留首条） ----
    parsed, errors = [], []          # parsed: 待入库行
    seen: set[tuple] = set()         # 文件内已出现键
    dup_in_file = 0                  # 文件内部重复数
    dup_examples: list[str] = []     # 重复示例（前 20 个，供展示）
    for lineno, row in enumerate(rows, start=1):
        if not row or not any(c.strip() for c in row):
            continue
        if len(row) < 3:
            errors.append(f"第 {lineno} 行：列数不足"); continue
        list_type, target, value = row[0].strip(), row[1].strip(), row[2].strip()
        enabled = row[3].strip().lower() not in ("0", "false", "no", "off", "") if len(row) > 3 else True
        remark = row[4].strip() if len(row) > 4 else ""
        try:
            # strict_tld=True：批量导入拒绝顶层通配（Task #177——
            # 批量无逐条确认环节，*.com 混在几百行里极易误入）
            _validate(list_type, target, value, strict_tld=True)
        except HTTPException as e:
            errors.append(f"第 {lineno} 行（{value or '空'}）：{e.detail}"); continue
        key = _key(list_type, target, value)
        if key in seen:
            dup_in_file += 1
            if len(dup_examples) < 20:
                dup_examples.append(f"{value}（第 {lineno} 行，文件内重复）")
            continue
        seen.add(key)
        parsed.append((list_type, target, value, int(enabled), remark))

    # ---- 阶段二：与库中已有条目比对（消重 + 跨名单冲突） ----
    dup_in_db = 0
    conflicts: list[str] = []        # 跨名单冲突明细（前 20 个）
    other_list = {"blacklist": "whitelist", "whitelist": "blacklist"}
    to_insert: list[tuple] = []
    if parsed:
        with db_cursor() as cur:
            cur.execute("SELECT list_type, target, value FROM filter_list")
            all_rows = cur.fetchall()
        existing = {(r["list_type"], r["target"], (r["value"] or "").strip().lower())
                    for r in all_rows}
        # 跨名单索引：(target, value.lower()) -> 已存在的名单类型集合
        by_value: dict[tuple, set] = {}
        for r in all_rows:
            by_value.setdefault((r["target"], (r["value"] or "").strip().lower()), set()) \
                    .add(r["list_type"])
        for item in parsed:
            list_type, target, value = item[0], item[1], item[2]
            key = _key(list_type, target, value)
            if key in existing:
                dup_in_db += 1
                if len(dup_examples) < 20:
                    dup_examples.append(f"{value}（已存在于名单中）")
                continue
            # 跨名单冲突：同值已存在于另一份名单
            opposite = other_list[list_type]
            vkey = (target, value.strip().lower())
            if opposite in by_value.get(vkey, set()):
                if len(conflicts) < 20:
                    conflicts.append(
                        f"{value}（已存在于{'白' if opposite == 'whitelist' else '黑'}名单中"
                        f"{'，白名单命中优先放行' if list_type == 'whitelist' else ''}）")
            to_insert.append(item)

    imported = 0
    if to_insert:
        with db_cursor() as cur:
            cur.executemany(
                """INSERT INTO filter_list
                   (list_type, target, value, enabled, remark, created_by)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                [(t, g, v, e, m, user) for (t, g, v, e, m) in to_insert],
            )
            imported = cur.rowcount if cur.rowcount and cur.rowcount > 0 else len(to_insert)
        from app.db import invalidate_list_cache
        invalidate_list_cache()
    deduped = dup_in_file + dup_in_db

    if imported:
        write_audit(user, "list_import", {
            "imported": imported, "skipped": len(errors),
            "deduped": deduped,
            "dup_in_file": dup_in_file, "dup_in_db": dup_in_db,
            "conflicts": len(conflicts),
        })
    return {"code": 0, "message": "ok",
            "data": {"imported": imported, "skipped": len(errors),
                     "deduped": deduped,
                     "dup_in_file": dup_in_file, "dup_in_db": dup_in_db,
                     "duplicates": dup_examples,
                     "conflicts": conflicts,
                     "errors": errors[:50]}}


@router.get("/export")
def export_items(
    list_type: str | None = None,
    user: str = Depends(get_current_user),
):
    """导出 CSV（utf-8-sig 带 BOM，Excel 直接打开不乱码）。"""
    where, params = "", []
    if list_type:
        where = "WHERE list_type=?"; params.append(list_type)
    with db_cursor() as cur:
        cur.execute(
            f"SELECT list_type, target, value, enabled, remark, created_by, "
            f"created_at, updated_at FROM filter_list {where} ORDER BY id",
            params,
        )
        rows = cur.fetchall()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["list_type", "target", "value", "enabled",
                     "remark", "created_by", "created_at", "updated_at"])
    for r in rows:
        writer.writerow([r["list_type"], r["target"], r["value"],
                         int(bool(r["enabled"])), r["remark"],
                         r["created_by"], r["created_at"], r["updated_at"]])

    return Response(
        content=buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="filter_list.csv"'},
    )
