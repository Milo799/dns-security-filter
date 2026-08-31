"""IP 检测结论缓存（LRU + TTL）—— 解析速度优化项（IP 后置过滤缓存）。

背景（2026-08-31 实测评估）：ip_postfilter 对每个应答 IP 实时调
query_threatintel_ip（在线源并发，最慢源 ≈ api_timeout_ms），且无缓存——
13 源启用时即便域名结论已走 domain_cache，单次查询仍被 IP 后置拖到
0.9~3.2s。热门域名应答 IP 集中（CDN Top IP 覆盖绝大多数流量），
IP 结论缓存命中率与域名缓存同级。

语义与 domain_cache 保持一致：
  - 缓存键：IP 字符串（strip 后原样；IPv4/IPv6 均精确匹配）
  - 缓存值：(is_malicious, reason, expire_at)
  - TTL：独立配置 ip_cache_ttl_s（默认 900s=15 分钟；IP 情报变化通常
    慢于域名情报，CDN IP 复用度高，可略长）
  - LRU：独立配置 ip_cache_size（默认 20 万条，单条约 150B ≈ 30MB）
  - fail-safe 结论不缓存：全源无结论的「默认拦截」不代表情报判定
    （调用方 skip_cache 控制，与 domain_cache 同规则）
  - 失效联动：情报源增删改/启停、融合策略切换时由路由层
    threatintel_invalidate() 一并清空

线程安全：读写共用一把锁（O(1) dict 操作，锁竞争可忽略）。
"""

import logging
import threading
import time
from collections import OrderedDict

from config import CONFIG

logger = logging.getLogger("platform.ip_cache")

_LOCK = threading.Lock()
_CACHE: OrderedDict[str, tuple[bool, str, float]] = OrderedDict()
# 命中统计（进程生命周期累计，供状态接口与压测观测）
STATS = {"hits": 0, "misses": 0}


def _maxsize() -> int:
    """容量上限（每次读配置，支持运行时热调）。最小 1024 防误配清零。"""
    try:
        return max(1024, int(CONFIG.ip_cache_size))
    except (TypeError, ValueError, AttributeError):
        return 200_000


def _ttl() -> float:
    """TTL 秒数（每次读配置，支持运行时热调）。最小 1s。"""
    try:
        return max(1.0, float(CONFIG.ip_cache_ttl_s))
    except (TypeError, ValueError, AttributeError):
        return 900.0


def get(ip: str) -> tuple[bool, str] | None:
    """读缓存。命中返回 (is_malicious, reason)，未命中/已过期返回 None。"""
    key = (ip or "").strip()
    if not key:
        return None
    now = time.monotonic()
    with _LOCK:
        item = _CACHE.get(key)
        if item is None:
            STATS["misses"] += 1
            return None
        is_malicious, reason, expire_at = item
        if now >= expire_at:              # 过期：惰性删除
            del _CACHE[key]
            STATS["misses"] += 1
            return None
        _CACHE.move_to_end(key)           # LRU 触碰
        STATS["hits"] += 1
        return is_malicious, reason


def put(ip: str, is_malicious: bool, reason: str) -> None:
    """写缓存（fail-safe 结论调用方负责不写入）。"""
    key = (ip or "").strip()
    if not key:
        return
    expire_at = time.monotonic() + _ttl()
    with _LOCK:
        _CACHE[key] = (is_malicious, reason, expire_at)
        _CACHE.move_to_end(key)
        if len(_CACHE) > _maxsize():      # LRU 淘汰最旧
            _CACHE.popitem(last=False)


def clear() -> None:
    """全量清空（测试用）。"""
    with _LOCK:
        _CACHE.clear()


def threatintel_invalidate() -> None:
    """情报源配置或融合策略变化时调用：全清缓存。

    与 domain_cache.threatintel_invalidate 同语义（路由层联动调用）。
    """
    size = 0
    with _LOCK:
        size = len(_CACHE)
        _CACHE.clear()
    if size:
        logger.info("情报配置变更，IP 检测缓存已清空（%d 条）", size)


def stats() -> dict:
    """缓存状态（容量 / 条目数 / 命中率），供状态接口与压测观测。"""
    with _LOCK:
        total = STATS["hits"] + STATS["misses"]
        return {
            "size": len(_CACHE),
            "max_size": _maxsize(),
            "hits": STATS["hits"],
            "misses": STATS["misses"],
            "hit_rate": round(STATS["hits"] / total, 4) if total else None,
        }
