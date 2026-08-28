"""域名检测结论缓存（LRU + TTL）—— 10 万终端规模前置开发项第 1 项。

检测主流程中最昂贵的环节是在线威胁情报多源并发查询
（query_threatintel_domain，线程池逐源查 HTTP/DNSBL，单次 1~5s）。
本地黑白名单与离线大名单已是内存 O(1) 匹配，无需缓存。

本模块只缓存「在线情报域名的检测结论」，语义：

  - 缓存键：规范化域名（lower + 去尾点）
  - 缓存值：(is_malicious, reason, expire_at)
  - TTL：默认 300s（可配 domain_cache_ttl_s；恶意结论与放行结论同 TTL，
    情报源对同一域名的判定变化通常以分钟计，短 TTL 平衡时效与吞吐）
  - LRU：默认 100 万条（可配 domain_cache_size；单条约 200B，
    100 万条约 200MB 内存上限，10 万终端下热门域名集远小于此）
  - fail-safe 结论不缓存：query_threatintel_domain 在全部源无结论时
    返回的「默认拦截」不代表情报判定，缓存会放大瞬时故障，故跳过——
    调用方传 skip_cache=True 实现（主流程用 reason 前缀识别）
  - 失效联动：情报源增删改/启停、融合策略切换时全量清空（低频管理操作，
    全清代价可接受，避免缓存键组合爆炸）；threatintel_invalidate() 由路由层调用

线程安全：读写共用一把锁（检测并发在线程池 run_in_executor，
读写均为 O(1) dict 操作，锁竞争可忽略；不用每键独立锁的复杂度）。
"""

import logging
import threading
import time
from collections import OrderedDict

from config import CONFIG

logger = logging.getLogger("platform.domain_cache")

_LOCK = threading.Lock()
_CACHE: OrderedDict[str, tuple[bool, str, float]] = OrderedDict()
# 命中统计（进程生命周期累计，供 /api/config 缓存信息展示与压测观测）
STATS = {"hits": 0, "misses": 0}


def _maxsize() -> int:
    """容量上限（每次读配置，支持运行时热调）。最小 1024 防误配清零。"""
    try:
        return max(1024, int(CONFIG.domain_cache_size))
    except (TypeError, ValueError, AttributeError):
        return 1_000_000


def _ttl() -> float:
    """TTL 秒数（每次读配置，支持运行时热调）。最小 1s。"""
    try:
        return max(1.0, float(CONFIG.domain_cache_ttl_s))
    except (TypeError, ValueError, AttributeError):
        return 300.0


def get(domain: str) -> tuple[bool, str] | None:
    """读缓存。命中返回 (is_malicious, reason)，未命中/已过期返回 None。"""
    key = (domain or "").strip().lower().rstrip(".")
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


def put(domain: str, is_malicious: bool, reason: str) -> None:
    """写缓存（fail-safe 结论调用方负责不写入）。"""
    key = (domain or "").strip().lower().rstrip(".")
    if not key:
        return
    expire_at = time.monotonic() + _ttl()
    with _LOCK:
        _CACHE[key] = (is_malicious, reason, expire_at)
        _CACHE.move_to_end(key)
        if len(_CACHE) > _maxsize():      # LRU 淘汰最旧
            _CACHE.popitem(last=False)


def clear() -> None:
    """全量清空（情报源变更 / 融合策略切换 / 测试用）。"""
    with _LOCK:
        _CACHE.clear()


def threatintel_invalidate() -> None:
    """情报源配置或融合策略变化时调用：全清缓存。

    路由层（threatintel.py 增删改源、切融合策略）调用；
    命名独立于 clear() 以显式表达业务语义。
    """
    size = 0
    with _LOCK:
        size = len(_CACHE)
        _CACHE.clear()
    if size:
        logger.info("情报配置变更，域名检测缓存已清空（%d 条）", size)


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
