"""银狐木马情报共享站 API 拉取适配器（迭代 43）。

数据源：微步在线"银狐"情报共享站 s.threatbook.com/cybercrime/silverfox。
银狐（SilverFox）是专打中文用户的远控木马家族（仿冒 DeepSeek/同花顺/
ToDesk/鲁大师官网投毒、钓鱼"人员名单"诱饵、C2 外联），该站由微步运营、
免登录共享事件级 IOC——2026-09-16 实测全量历史事件（2023-06 至今，
1175 个）与事件级 IOC（related_ioc_list_v2）均可匿名拉取，无 API Key、
无配额。

与文件下载型离线源（hagezi/StevenBlack 等）不同，本源是"API 拉取型"：
数据不在单个 URL 的文本文件里，而是分两步聚合——
  1) get-humans?startTime&endTime（毫秒时间戳窗口，92 天一窗回溯）
     → 事件列表（uuid）；
  2) get-human?uuid → 事件详情，related_ioc_list_v2 含
     {domain, ip, ioc, url, hash} 分类 IOC 列表。
另有 get-hot-ioc（每日热点 15 域名 + 15 IP）作增量补充。

注意：以上是非官方前端 XHR 接口（无文档无授权承诺），可能随站点改版
变更——拉取失败按"导入失败"处理，保留库中旧数据整源不动（fail-safe），
绝不影响 DNS 检测主路径。

导入语义（threat_list.import_api_source）：
  - 域名 → target=domain（检测链 4.5 段，父域后缀匹配与人工名单一致）；
  - IP   → target=ip（PTR 反查路径 find_ip 命中拦截）；
  - hash 全部丢弃（对 DNS 路径无意义）；URL 提取 host 并入域名；
  - 整源替换：重复拉取即增量更新，滚动窗口外的旧事件 IOC 自动淘汰。

限速：0.3s/请求（全量 1175 事件约 6 分钟，后台任务化不阻塞请求）。
出站走 app.http_client 共享 Client（生产环境自动经内网代理）。
"""

import ipaddress
import logging
import re
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse

from config import CONFIG

from app import http_client

logger = logging.getLogger("platform.app.silverfox")

_BASE = "https://s.threatbook.com"
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Referer": _BASE + "/cybercrime/silverfox",
}

# 站点首个事件收录时间（2023-06）；全量回溯从此开始
_FIRST_EVENT = datetime(2023, 6, 1)

# 事件列表接口的时间窗口步长（天）：92 天一窗，实测单窗返回无分页上限
_WINDOW_DAYS = 92

# 请求间隔（秒）：对共享站保持克制，全量 1175 事件 ≈ 6 分钟
_REQUEST_INTERVAL = 0.3

# 连续失败熔断：连续 N 个事件详情拉取失败视为接口已变更/被封，
# 中止本轮（避免无意义打满重试；库中旧数据保留）
_MAX_CONSECUTIVE_FAILS = 30

_RE_DOMAIN = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
_RE_HASH = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$",
                      re.IGNORECASE)


def classify(value) -> tuple[str, str] | None:
    """单条 IOC 分类：返回 ("domain"|"ip", 规范值) 或 None（丢弃）。

    - SHA 哈希丢弃（DNS 路径无意义）；
    - IPv4/IPv6 字面量 → ip；
    - 合法域名（含子域）→ domain；
    - 带协议/路径的 URL 交给 _url_hosts 处理，这里不认。
    """
    s = str(value or "").strip().strip(".").lower()
    if not s or len(s) > 253 or _RE_HASH.match(s):
        return None
    # IPv4 / IPv6 字面量
    try:
        ipaddress.ip_address(s)
        return ("ip", s)
    except ValueError:
        pass
    if "%" in s or " " in s or "/" in s or ":" in s:
        return None              # 带端口/路径/通配/掩码等，非裸条目
    if _RE_DOMAIN.match(s) and "." in s:
        return ("domain", s)
    return None


def _url_hosts(urls) -> set[str]:
    """从 URL 列表提取 host 域名（银狐投毒链接的域名有额外价值）。"""
    out: set[str] = set()
    for u in urls or []:
        s = str(u or "").strip()
        if not s.lower().startswith(("http://", "https://")):
            continue
        try:
            host = urlparse(s).hostname
        except ValueError:
            continue
        if host:
            r = classify(host)
            if r and r[0] == "domain":
                out.add(r[1])
    return out


def _walk_strings(node) -> list[str]:
    """递归提取 JSON 中全部字符串叶子（get-hot-ioc 结构无文档，
    防御性全量收割后靠 classify 过滤——标签/数字不会匹配域名/IP）。"""
    out: list[str] = []
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for v in node.values():
            out.extend(_walk_strings(v))
    elif isinstance(node, (list, tuple)):
        for v in node:
            out.extend(_walk_strings(v))
    return out


def _get_json(path: str, params: dict | None = None, retries: int = 3) -> dict:
    """GET 并解析 JSON；重试指数退避，最终失败抛异常由调用方处理。"""
    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            resp = http_client.get(_BASE + path, headers=_HEADERS,
                                   params=params, timeout=25.0)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:      # noqa: BLE001 统一重试
            last_exc = e
            if attempt < retries - 1:
                time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"银狐接口请求失败 {path}: {last_exc}")


def _list_events(start: datetime, end: datetime, progress=None) -> list[str]:
    """按 92 天窗口回溯拉取事件 uuid 列表（去重保序）。"""
    uuids: list[str] = []
    cur = start
    while cur < end:
        nxt = min(cur + timedelta(days=_WINDOW_DAYS), end)
        d = _get_json("/apis/cybercrime-trend/get-humans", {
            "startTime": int(cur.timestamp() * 1000),
            "endTime": int(nxt.timestamp() * 1000),
        })
        events = ((d.get("data") or {}).get("data")) or []
        uuids.extend(e["uuid"] for e in events if e.get("uuid"))
        if progress is not None:
            progress.update(
                message=f"拉取事件列表… 已发现 {len(uuids)} 个事件")
        cur = nxt
        time.sleep(_REQUEST_INTERVAL)
    return list(dict.fromkeys(uuids))


def _merge_event_iocs(detail: dict, domains: set, ips: set) -> None:
    """把单个事件详情里的 IOC 合并进集合（domain/ioc/ip/url 四类）。"""
    iocs = (detail.get("data") or {}).get("related_ioc_list_v2") or {}
    for key in ("domain", "ioc"):
        for x in iocs.get(key) or []:
            r = classify(x)
            if r:
                (ips if r[0] == "ip" else domains).add(r[1])
    for x in iocs.get("ip") or []:
        r = classify(x)
        if r and r[0] == "ip":
            ips.add(r[1])
    domains |= _url_hosts(iocs.get("url"))


def fetch_iocs(progress: dict | None = None,
               window_days: int | None = None) -> dict:
    """全量拉取银狐 IOC，返回 {domains, ips, events, failed_events}。

    - window_days：回溯窗口（天）。None 时读 CONFIG.silverfox_window_days，
      0 = 全量回溯至 2023-06 站点首个事件（用户拍板"一个不漏"）；
      N>0 时只拉近 N 天的事件（控制老 IOC 误拦风险，滚动窗口外整源淘汰）。
    - 空结果保护：域名与 IP 双空时抛异常（整源替换导入 0 条会清掉旧数据，
      上游改版/被拦时的兜底）；
    - 连续失败熔断：连续 30 个事件拉取失败判定接口异常，中止并抛出。
    - progress：复用 threat_list 导入任务进度字典（download 阶段），
      parsed=已处理事件数、total=事件总数、message=阶段文案。
    """
    if window_days is None:
        try:
            window_days = int(getattr(CONFIG, "silverfox_window_days", 0) or 0)
        except (TypeError, ValueError):
            window_days = 0
    window_days = max(0, window_days)

    now = datetime.now()
    start = (now - timedelta(days=window_days)) if window_days > 0 else _FIRST_EVENT

    if progress is not None:
        progress.update(stage="download", parsed=0, total=0,
                        message="拉取银狐事件列表…")

    uuids = _list_events(start, now + timedelta(days=1), progress=progress)
    if not uuids:
        raise RuntimeError(
            "银狐事件列表为空（接口可能已变更或被拦截），中止导入以保留旧数据")

    if progress is not None:
        progress.update(total=len(uuids),
                        message=f"逐事件拉取 IOC 0/{len(uuids)}…")

    domains: set[str] = set()
    ips: set[str] = set()
    failed = 0
    consecutive_fails = 0
    for i, uid in enumerate(uuids, 1):
        try:
            detail = _get_json("/apis/cybercrime-trend/get-human",
                               {"uuid": uid})
            _merge_event_iocs(detail, domains, ips)
            consecutive_fails = 0
        except Exception as e:      # noqa: BLE001 单事件失败不中断整轮
            failed += 1
            consecutive_fails += 1
            logger.warning("银狐事件 %s 拉取失败（%d/%d）：%s",
                           uid, i, len(uuids), e)
            if consecutive_fails >= _MAX_CONSECUTIVE_FAILS:
                raise RuntimeError(
                    f"银狐接口连续 {consecutive_fails} 个事件拉取失败，"
                    "疑似接口变更或被限流，中止导入以保留旧数据")
        if progress is not None:
            progress.update(
                parsed=i,
                message=f"逐事件拉取 IOC {i}/{len(uuids)} · "
                        f"域名 {len(domains)} · IP {len(ips)}")
        time.sleep(_REQUEST_INTERVAL)

    # 每日热点补充（结构无文档，防御性全量字符串收割后分类过滤）
    try:
        hot = _get_json("/apis/cybercrime-trend/get-hot-ioc")
        for s in _walk_strings(hot):
            r = classify(s)
            if r:
                (ips if r[0] == "ip" else domains).add(r[1])
    except Exception as e:          # noqa: BLE001 热点失败不影响主数据
        logger.warning("银狐每日热点拉取失败（不影响事件数据）：%s", e)

    domains -= ips                  # IP 集合与域名集合互斥
    if not domains and not ips:
        raise RuntimeError("银狐 IOC 拉取结果为空，中止导入以保留旧数据")

    logger.info("银狐 IOC 拉取完成：事件 %d（失败 %d）、域名 %d、IP %d",
                len(uuids), failed, len(domains), len(ips))
    return {"domains": sorted(domains), "ips": sorted(ips),
            "events": len(uuids), "failed_events": failed}
