"""离线大名单：hagezi / StevenBlack 等恶意域名列表导入与本地离线匹配。

与在线威胁情报源（HTTP API）不同，大名单一次导入本地 SQLite（threat_list 表），
检测时内存 O(1) 匹配，零外部 API 依赖、零延迟、无 Key。

特性：
  - 内置来源元数据（hagezi 威胁情报完整版 / hagezi 威胁情报精简 mini / hagezi 综合大名单 /
    StevenBlack hosts / URLhaus 恶意域名 / OISD 综合大名单），
    支持自定义 URL 导入任意纯域名 / hosts / adblock 格式列表；
  - 导入为"事务内整源替换"：重复导入即增量更新，不留陈旧条目；
  - 来源可整体启停（enabled），停用后不再参与匹配（条目保留，重新启用即恢复）；
  - 自动更新按来源各自周期调度（update_interval_s）：URLhaus 高及时小名单
    30 分钟同步，大名单每日同步，见 auto_update.py / auto_update_once()；
  - 匹配语义：域名精确匹配 + 逐级父域后缀匹配（列表含 bad.com，则 a.bad.com 命中）；
    IP 精确匹配；
  - 内存缓存：导入后 invalidate()，下次检测自动重载，进程内保持一致。

注意：hagezi 的 "ULTIMATE"（domains.txt）含广告/追踪，量最大、误伤面也大，
默认建议用 "threat-intelligence.txt"（纯安全情报）或 "mini"（精简版，内存占用约完整版 1/20）；
URLhaus 为"当前活跃"哨兵名单，误伤极小但规模小，适合与全量大名单叠加使用。
"""

import ipaddress
import logging
import re
from datetime import datetime

import httpx

from app.db import db_cursor

logger = logging.getLogger("platform.app.threat_list")

# 内置来源元数据（URL 可随上游仓库调整；格式 plain / hosts / auto）
# - update_interval_s：自动更新周期（秒）。高及时小名单（如 URLhaus）配短周期，
#   大名单配每日；auto_update 调度按各源最近导入时间判断是否到期。
# - 注意：hagezi / oisd 仓库的 raw 主地址不可达时，download() 自动降级到
#   jsDelivr CDN（见 _MIRROR_RULES）。
SOURCES = [
    {
        "key": "hagezi_ti",
        "name": "hagezi 威胁情报",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt",
        "format": "auto",
        "description": "hagezi DNS Blocklists · TIF 威胁情报（恶意软件/钓鱼/C2/欺诈），完整版约 210 万条、36MB，量最大、误伤最小的安全专项名单",
        "max_bytes": 100 * 1024 * 1024,
        "update_interval_s": 24 * 3600,
    },
    {
        "key": "hagezi_mini",
        "name": "hagezi 威胁情报（精简 mini）",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt",
        "format": "auto",
        "description": "hagezi DNS Blocklists · TIF Mini 精简版（恶意软件/钓鱼/C2/欺诈），约 8.6 万条、3MB，仅收录已确认威胁主域、误杀最少，内存缓存占用约为完整版的 1/20，适合资源受限部署",
        "max_bytes": 20 * 1024 * 1024,
        "update_interval_s": 24 * 3600,
    },
    {
        "key": "hagezi_ult",
        "name": "hagezi 综合大名单",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt",
        "format": "auto",
        "description": "hagezi DNS Blocklists · ULTIMATE 全量（恶意+广告+追踪），约 27 万条，量最大，误伤面也大",
        "max_bytes": 200 * 1024 * 1024,
        "update_interval_s": 24 * 3600,
    },
    {
        "key": "stevenblack",
        "name": "StevenBlack hosts",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "format": "hosts",
        "description": "StevenBlack/hosts 统一 hosts（广告/恶意/追踪合并版），约 15 万条",
        "max_bytes": 100 * 1024 * 1024,
        "update_interval_s": 24 * 3600,
    },
    {
        "key": "urlhaus",
        "name": "URLhaus 恶意域名",
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "format": "hosts",
        "description": "abuse.ch URLhaus 当前活跃恶意软件分发域名，约 300-2000 条、10-100KB，2-4 分钟更新；本项目 30 分钟同步一次，作为高及时哨兵名单",
        "max_bytes": 10 * 1024 * 1024,
        "update_interval_s": 30 * 60,
    },
    {
        "key": "oisd",
        "name": "OISD 综合大名单",
        "url": "https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild_big.txt",
        "format": "plain",
        "description": "OISD Big（Block. Don't break.）恶意/广告/追踪综合名单，约 20 万条、2MB，每日更新、低误报，与 hagezi 互为独立交叉验证",
        "max_bytes": 20 * 1024 * 1024,
        "update_interval_s": 24 * 3600,
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


def parse_content(text: str, fmt: str = "auto",
                  progress: dict | None = None) -> list[str]:
    """解析列表文本 → 规范化域名列表（去重保序）。

    - plain: 每行一个域名（hagezi txt）；同时兼容 adblock ||x^ 与 URL 行
    - hosts: StevenBlack 格式 "0.0.0.0 domain"，跳过注释与本地保留项
    - auto: 按首个有效行内容判断（有 IP 前缀列 → hosts，否则 plain）
    - progress: 可选进度字典，解析过程中更新 parsed（已处理行数）
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

    for i, ln in enumerate(lines):
        if progress is not None and i % 50000 == 0:
            progress["parsed"] = i
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
    if progress is not None:
        progress["parsed"] = len(lines)
    return out


# ---------------------------------------------------------------------------
# 下载（主地址失败自动降级镜像，提升国内可达性）
# ---------------------------------------------------------------------------

# 已知镜像映射：GitHub 仓库 raw → jsDelivr CDN（官方推荐，国内访问更稳）
_MIRROR_RULES = [
    ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/",
     "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/"),
    ("https://raw.githubusercontent.com/sjhgvr/oisd/main/",
     "https://cdn.jsdelivr.net/gh/sjhgvr/oisd@main/"),
]


def _mirror_of(url: str) -> str | None:
    """按规则推导镜像地址；无匹配返回 None。"""
    for src, dst in _MIRROR_RULES:
        if url.startswith(src):
            return dst + url[len(src):]
    return None


def _download_once(url: str, max_bytes: int, timeout_s: int,
                   progress: dict | None = None) -> str:
    """单次流式下载列表文本；超限/失败抛异常由调用方处理。

    progress（可选）：更新 downloaded（已收字节）与 total_bytes
    （Content-Length，服务端未返回时为 0 表示未知）。
    """
    with httpx.stream(
        "GET", url,
        headers={"User-Agent": "dns-security-filter/1.0"},
        timeout=timeout_s, follow_redirects=True,
    ) as resp:
        resp.raise_for_status()
        if progress is not None:
            try:
                progress["total_bytes"] = int(resp.headers.get(
                    "content-length") or 0)
            except ValueError:
                progress["total_bytes"] = 0
        chunks, total = [], 0
        for chunk in resp.iter_bytes(65536):
            total += len(chunk)
            if progress is not None:
                progress["downloaded"] = total
            if total > max_bytes:
                raise ValueError(f"列表超过大小上限 {max_bytes} 字节")
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def download(url: str, max_bytes: int = 100 * 1024 * 1024,
             timeout_s: int = 60, progress: dict | None = None) -> str:
    """下载列表文本；主地址失败（网络/超时/HTTP 错误）自动尝试镜像 URL。

    - 仅已知镜像规则的地址（目前 hagezi 仓库）会降级；
    - 镜像也失败时抛出最后一次异常，由调用方决定是否报错；
    - progress 透传各阶段字节进度。
    """
    try:
        return _download_once(url, max_bytes, timeout_s, progress)
    except Exception:
        mirror = _mirror_of(url)
        if mirror is None:
            raise
        logger.warning("主地址下载失败，降级镜像：%s", mirror)
        return _download_once(mirror, max_bytes, timeout_s, progress)


# ---------------------------------------------------------------------------
# 导入 / 状态（SQLite）
# ---------------------------------------------------------------------------

def import_source(source: str, text: str, enabled: bool = True,
                  progress: dict | None = None) -> int:
    """整源替换导入：DELETE 后批量 INSERT（事务内），返回实际导入条数。

    重复导入即增量更新；enabled 仅影响本批次默认启用状态（后续可整体切换）。
    progress（可选）：解析后置 total 为总条数，分批入库时更新 inserted。
    """
    values = parse_content(text, progress=progress)
    rows = [(source, v, "domain", int(enabled)) for v in values]
    if progress is not None:
        progress.update(stage="insert", total=len(rows),
                        message=f"入库中 0/{len(rows)}")
    with db_cursor() as cur:
        cur.execute("DELETE FROM threat_list WHERE source=?", (source,))
        BATCH = 50000
        for i in range(0, len(rows), BATCH):
            cur.executemany(
                """INSERT INTO threat_list (source, value, target, enabled)
                   VALUES (?, ?, ?, ?)""",
                rows[i:i + BATCH],
            )
            if progress is not None:
                done = min(i + BATCH, len(rows))
                progress.update(inserted=done, message=f"入库中 {done}/{len(rows)}")
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
# 导入任务进度（进程内存态，供前端轮询展示）
# ---------------------------------------------------------------------------

_IMPORT_TASKS: dict[str, dict] = {}


def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _task(source: str) -> dict:
    t = _IMPORT_TASKS.get(source)
    if t is None:
        t = {
            "source": source, "status": "idle", "stage": "",
            "downloaded": 0, "total_bytes": 0,
            "parsed": 0, "inserted": 0, "total": 0,
            "message": "", "error": None,
            "started_at": None, "finished_at": None,
        }
        _IMPORT_TASKS[source] = t
    return t


def begin_import(source: str) -> dict | None:
    """标记某来源导入开始；已有 running 任务时返回 None（拒绝并发）。"""
    t = _task(source)
    if t["status"] == "running":
        return None
    t.update(status="running", stage="download",
             downloaded=0, total_bytes=0, parsed=0, inserted=0, total=0,
             message="准备下载…", error=None,
             started_at=_now_str(), finished_at=None)
    return t


def import_progress(source: str | None = None) -> dict | list[dict]:
    """查询导入进度；source 省略时返回全部来源（诊断/测试用）。"""
    if source is not None:
        return _task(source)
    return list(_IMPORT_TASKS.values())


# ---------------------------------------------------------------------------
# 自动更新（方案 A：服务内定时任务，由 app/auto_update.py 调度）
# ---------------------------------------------------------------------------

def enabled_source_keys() -> list[str]:
    """当前已导入且启用中的来源 key（自动更新的目标列表）。"""
    with db_cursor() as cur:
        cur.execute(
            "SELECT DISTINCT source FROM threat_list WHERE enabled=1")
        return [r["source"] for r in cur.fetchall()]


def source_due(key: str, interval_s: int) -> bool:
    """判断来源是否到了自动更新周期（按数据库最近导入时间）。

    - 从未导入 / 时间无法解析 → 视为到期（允许尝试）；
    - 距最近导入 >= interval_s → 到期；
    - 测试可直接调用。
    """
    with db_cursor() as cur:
        cur.execute(
            "SELECT MAX(updated_at) AS t FROM threat_list WHERE source=?",
            (key,))
        row = cur.fetchone()
    if row is None or row["t"] is None:
        return True
    try:
        last = datetime.strptime(str(row["t"]), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return True
    return (datetime.now() - last).total_seconds() >= interval_s


def auto_update_once() -> dict:
    """同步执行一轮自动更新：对每个"已启用"的内置来源下载并整源替换。

    - 仅更新内置来源；自定义来源未存 URL 元数据，无法自动更新，保持手工导入；
    - 每个来源按 update_interval_s 判断是否到期（未到期跳过，标记 skipped）；
      高及时小名单（如 urlhaus 30 分钟）与大名单（每日）在同一轮调度中并存；
    - 单来源失败不影响其他来源（隔离）；
    - 返回 {source_key: {"ok": bool, "imported": int, "error": str|None,
      "skipped": bool}}。
    """
    meta = _source_meta()
    results: dict = {}
    for key in enabled_source_keys():
        if key not in meta:      # 非内置来源跳过
            continue
        if _task(key)["status"] == "running":   # 手工导入进行中，避免并发写
            results[key] = {"ok": False, "imported": 0,
                            "error": "该来源正在手工导入中，跳过本次自动更新"}
            continue
        info = meta[key]
        interval = info.get("update_interval_s", 24 * 3600)
        if not source_due(key, interval):
            results[key] = {"ok": True, "imported": 0, "error": None,
                            "skipped": True}
            logger.debug("离线大名单自动更新 %s 未到周期（%ds），跳过", key, interval)
            continue
        try:
            text = download(info["url"], info.get("max_bytes", 100 * 1024 * 1024),
                            timeout_s=90)
            n = import_source(key, text, enabled=True)
            results[key] = {"ok": True, "imported": n, "error": None,
                            "skipped": False}
            logger.info("离线大名单自动更新 %s 完成：%d 条", key, n)
        except Exception as e:   # 隔离失败，绝不中断整轮
            results[key] = {"ok": False, "imported": 0, "error": str(e),
                            "skipped": False}
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
