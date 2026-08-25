"""离线大名单：hagezi / StevenBlack 等恶意域名列表导入与本地离线匹配。

与在线威胁情报源（HTTP API）不同，大名单一次导入本地 SQLite（threat_list 表），
检测时内存 O(1) 匹配，零外部 API 依赖、零延迟、无 Key。

特性：
  - 内置来源元数据（hagezi 威胁情报 / hagezi 综合大名单 / StevenBlack hosts），
    支持自定义 URL 导入任意纯域名 / hosts / adblock 格式列表；
  - 导入为"事务内整源替换"：重复导入即增量更新，不留陈旧条目；
  - 来源可整体启停（enabled），停用后不再参与匹配（条目保留，重新启用即恢复）；
  - 匹配语义：域名精确匹配 + 逐级父域后缀匹配（列表含 bad.com，则 a.bad.com 命中）；
    IP 精确匹配；
  - 内存缓存：导入后 invalidate()，下次检测自动重载，进程内保持一致。

注意：hagezi 的 "ULTIMATE"（domains.txt）含广告/追踪，量最大、误伤面也大，
默认建议用 "threat-intelligence.txt"（纯安全情报）。
"""

import ipaddress
import logging
import re

import httpx

from app.db import db_cursor

logger = logging.getLogger("platform.app.threat_list")

# 内置来源元数据（URL 可随上游仓库调整；格式 plain / hosts / auto）
SOURCES = [
    {
        "key": "hagezi_ti",
        "name": "hagezi 威胁情报",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/threat-intelligence.txt",
        "format": "auto",
        "description": "hagezi DNS Blocklists · 纯安全威胁情报（恶意软件/钓鱼/C2/欺诈），量最大、误伤最小的安全专项名单",
        "max_bytes": 100 * 1024 * 1024,
    },
    {
        "key": "hagezi_ult",
        "name": "hagezi 综合大名单",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/domains.txt",
        "format": "auto",
        "description": "hagezi DNS Blocklists · ULTIMATE 全量（恶意+广告+追踪），量最大，误伤面也大",
        "max_bytes": 200 * 1024 * 1024,
    },
    {
        "key": "stevenblack",
        "name": "StevenBlack hosts",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "format": "hosts",
        "description": "StevenBlack/hosts 统一 hosts（广告/恶意/追踪合并版），约 15 万条",
        "max_bytes": 100 * 1024 * 1024,
    },
]

# 内部状态：source 元数据表（含数据库统计，运行时刷新）
def _source_meta() -> dict:
    return {s["key"]: dict(s) for s in SOURCES}


# ---------------------------------------------------------------------------
# 解析
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")

# hosts 文件里的本地重定向行，导入时跳过（不是恶意条目）
_LOCAL_ONLY = {"localhost", "localhost.localdomain", "broadcasthost",
               "0.0.0.0", "127.0.0.1", "255.255.255.255", "::1", "fe80::1",
               "localhost.local", "ip6-localhost", "ip6-loopback"}


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _normalize_domain(raw: str) -> str | None:
    """规范化单条域名：去协议/路径/端口/通配符/尾点，非法返回 None。"""
    s = raw.strip().lower()
    if not s or s.startswith("#"):
        return None
    # adblock 格式：||example.com^
    if s.startswith("||"):
        s = s[2:]
    if s.endswith("^"):
        s = s[:-1]
    # 常见协议（含混淆写法 hxxp）
    for p in ("https://", "http://", "hxxps://", "hxxp://"):
        if s.startswith(p):
            s = s[len(p):]
            break
    # 去路径与端口
    if "/" in s:
        s = s.split("/", 1)[0]
    if s.startswith("["):            # IPv6 字面量 [::1]
        s = s.split("]", 1)[0]
    elif ":" in s:
        s = s.split(":", 1)[0]
    s = s.rstrip(".").strip()
    if not s or len(s) > 253 or s in _LOCAL_ONLY:
        return None
    # 通配符条目（hosts 中罕见）按主域处理
    if s.startswith("*."):
        s = s[2:]
    if s.startswith("*") or s.startswith("."):
        s = s.lstrip("*.")
    if _is_ip(s):
        return None                # hosts 前缀 IP 属重定向目标，非条目本身
    if not _DOMAIN_RE.match(s):
        return None
    return s


def parse_content(text: str, fmt: str = "auto") -> list[str]:
    """解析列表文本 → 规范化域名列表（去重保序）。

    - plain: 每行一个域名（hagezi txt）；同时兼容 adblock ||x^ 与 URL 行
    - hosts: StevenBlack 格式 "0.0.0.0 domain"，跳过注释与本地保留项
    - auto: 按首个有效行内容判断（有 IP 前缀列 → hosts，否则 plain）
    """
    out: list[str] = []
    seen: set[str] = set()
    lines = (text or "").splitlines()
    effective = fmt
    if fmt == "auto":
        for ln in lines[:50]:
            t = ln.strip()
            if not t or t.startswith("#"):
                continue
            first = t.split(None, 1)[0]
            effective = "hosts" if _is_ip(first) else "plain"
            break

    for ln in lines:
        raw = ln.strip()
        if not raw or raw.startswith("#"):
            continue
        if effective == "hosts":
            parts = raw.split()
            if len(parts) < 2:
                continue
            value = parts[1].strip()
            if value.startswith("#"):
                continue
        else:
            value = raw
        d = _normalize_domain(value)
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


# ---------------------------------------------------------------------------
# 下载
# ---------------------------------------------------------------------------

def download(url: str, max_bytes: int = 100 * 1024 * 1024,
             timeout_s: int = 60) -> str:
    """流式下载列表文本；超限/失败抛异常由调用方处理。"""
    with httpx.stream(
        "GET", url,
        headers={"User-Agent": "dns-security-filter/1.0"},
        timeout=timeout_s, follow_redirects=True,
    ) as resp:
        resp.raise_for_status()
        chunks, total = [], 0
        for chunk in resp.iter_bytes(65536):
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"列表超过大小上限 {max_bytes} 字节")
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# 导入 / 状态（SQLite）
# ---------------------------------------------------------------------------

def import_source(source: str, text: str, enabled: bool = True) -> int:
    """整源替换导入：DELETE 后批量 INSERT（事务内），返回实际导入条数。

    重复导入即增量更新；enabled 仅影响本批次默认启用状态（后续可整体切换）。
    """
    values = parse_content(text)
    rows = [(source, v, "domain", int(enabled)) for v in values]
    with db_cursor() as cur:
        cur.execute("DELETE FROM threat_list WHERE source=?", (source,))
        if rows:
            cur.executemany(
                """INSERT INTO threat_list (source, value, target, enabled)
                   VALUES (?, ?, ?, ?)""",
                rows,
            )
    invalidate()
    logger.info("离线大名单 %s 导入 %d 条", source, len(rows))
    return len(rows)


def enable_source(source: str, enabled: bool) -> int:
    """整体启停某来源的全部条目，返回影响条数。"""
    with db_cursor() as cur:
        cur.execute("UPDATE threat_list SET enabled=? WHERE source=?",
                    (int(enabled), source))
        n = cur.rowcount
    invalidate()
    return n


def delete_source(source: str) -> int:
    """清空某来源的全部条目，返回删除条数。"""
    with db_cursor() as cur:
        cur.execute("DELETE FROM threat_list WHERE source=?", (source,))
        n = cur.rowcount
    invalidate()
    return n


# ---------------------------------------------------------------------------
# 自动更新（方案 A：服务内定时任务，由 app/auto_update.py 调度）
# ---------------------------------------------------------------------------

def enabled_source_keys() -> list[str]:
    """当前已导入且启用中的来源 key（自动更新的目标列表）。"""
    with db_cursor() as cur:
        cur.execute(
            "SELECT DISTINCT source FROM threat_list WHERE enabled=1")
        return [r["source"] for r in cur.fetchall()]


def auto_update_once() -> dict:
    """同步执行一轮自动更新：对每个"已启用"的内置来源下载并整源替换。

    - 仅更新内置来源（hagezi_ti / hagezi_ult / stevenblack）；
      自定义来源未存 URL 元数据，无法自动更新，保持手工导入；
    - 单来源失败不影响其他来源（隔离）；
    - 返回 {source_key: {"ok": bool, "imported": int, "error": str|None}}。
    """
    meta = _source_meta()
    results: dict = {}
    for key in enabled_source_keys():
        if key not in meta:      # 非内置来源跳过
            continue
        info = meta[key]
        try:
            text = download(info["url"], info.get("max_bytes", 100 * 1024 * 1024),
                            timeout_s=90)
            n = import_source(key, text, enabled=True)
            results[key] = {"ok": True, "imported": n, "error": None}
            logger.info("离线大名单自动更新 %s 完成：%d 条", key, n)
        except Exception as e:   # 隔离失败，绝不中断整轮
            results[key] = {"ok": False, "imported": 0, "error": str(e)}
            logger.warning("离线大名单自动更新 %s 失败：%s", key, e)
    return results


def source_stats() -> dict:
    """各来源统计：条数 / 启用条数 / 最近导入时间。"""
    meta = _source_meta()
    with db_cursor() as cur:
        cur.execute(
            """SELECT source,
                      COUNT(*) AS total,
                      SUM(CASE WHEN enabled=1 THEN 1 ELSE 0 END) AS enabled_cnt,
                      MAX(updated_at) AS updated_at
               FROM threat_list GROUP BY source""")
        for row in cur.fetchall():
            key = row["source"]
            if key not in meta:
                continue
            meta[key]["total"] = row["total"]
            meta[key]["enabled_cnt"] = row["enabled_cnt"] or 0
            meta[key]["updated_at"] = row["updated_at"]
    for s in meta.values():
        s.setdefault("total", 0)
        s.setdefault("enabled_cnt", 0)
        s.setdefault("updated_at", None)
    return meta


def list_entries(source: str, keyword: str = "",
                 enabled: bool | None = None,
                 page: int = 1, size: int = 50) -> dict:
    """分页列出某来源的具体条目（查看 / 排查用）。

    - keyword 对 value 做子串模糊匹配（不区分大小写，值本身已小写）；
    - enabled=None 返回全部状态，True/False 仅返回对应状态；
    - page 从 1 起，size 上限 500；
    - 返回 {"total": 总数, "items": [{id, value, target, enabled,
      created_at, updated_at}]}。
    """
    page = max(1, int(page))
    size = min(max(1, int(size)), 500)
    where, args = ["source = ?"], [source]
    if keyword:
        where.append("value LIKE ?")
        args.append(f"%{keyword.strip().lower()}%")
    if enabled is not None:
        where.append("enabled = ?")
        args.append(1 if enabled else 0)
    cond = " AND ".join(where)
    with db_cursor() as cur:
        cur.execute(f"SELECT COUNT(*) AS c FROM threat_list WHERE {cond}",
                    args)
        total = cur.fetchone()["c"]
        cur.execute(
            f"""SELECT id, value, target, enabled, created_at, updated_at
                FROM threat_list WHERE {cond}
                ORDER BY value LIMIT ? OFFSET ?""",
            args + [size, (page - 1) * size])
        items = [dict(r) for r in cur.fetchall()]
    return {"total": total, "items": items}


# ---------------------------------------------------------------------------
# 内存缓存匹配（检测主流程调用）
# ---------------------------------------------------------------------------

_DOMAIN_CACHE: dict[str, str] | None = None   # value -> source（仅 enabled 条目）
_IP_CACHE: dict[str, str] | None = None


def invalidate() -> None:
    """导入/启停/删除后调用，下次匹配自动重载。"""
    global _DOMAIN_CACHE, _IP_CACHE
    _DOMAIN_CACHE = None
    _IP_CACHE = None


def _load_cache() -> None:
    global _DOMAIN_CACHE, _IP_CACHE
    if _DOMAIN_CACHE is not None:
        return
    doms: dict[str, str] = {}
    ips: dict[str, str] = {}
    with db_cursor() as cur:
        cur.execute(
            "SELECT value, target, source FROM threat_list WHERE enabled=1")
        for row in cur.fetchall():
            (doms if row["target"] == "domain" else ips)[row["value"]] = \
                row["source"]
    _DOMAIN_CACHE, _IP_CACHE = doms, ips


def check_domain(domain: str) -> bool:
    """检测主流程用：域名是否命中离线大名单（精确 + 逐级父域后缀）。"""
    return find_domain(domain) is not None


def find_domain(domain: str) -> tuple[str, str] | None:
    """命中返回 (source, 命中的列表条目)；未命中返回 None。"""
    _load_cache()
    d = (domain or "").strip().lower().rstrip(".")
    if not d:
        return None
    while d:
        src = _DOMAIN_CACHE.get(d)
        if src is not None:
            return src, d
        idx = d.find(".")
        if idx < 0:
            break
        d = d[idx + 1:]
    return None


def check_ip(ip: str) -> bool:
    """检测主流程用：IP 是否命中离线大名单（精确匹配）。"""
    return find_ip(ip) is not None


def find_ip(ip: str) -> tuple[str, str] | None:
    _load_cache()
    src = _IP_CACHE.get((ip or "").strip())
    return (src, ip.strip()) if src is not None else None
