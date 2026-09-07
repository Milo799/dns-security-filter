"""重复查询计数消解（迭代 36）——"今日请求"虚高治本。

问题（生产 2026-09-07 观察）：今日请求/今日放行比终端真实查询量
明显偏大。根因 = Windows DNS 转发器超时重发：转发器默认 3~4s 超时
自动重试 1~2 次，检测链路对域缓存过期重检/冷域名场景耗时 0.6~1.3s+
（在线 DNSBL 出站 + 上游递归解析 + IP 后置），偶发慢源叠加后单查询
耗时超转发器阈值 → 转发器判定丢包重发同一查询 → 每次重发都作为
新查询进入 process_query 被 query_stats.record 计数（本地已复现：
同查询发两次 total=2）。

方案：process_query 入口按 (client_ip, domain, qtype) 做 N 秒滑动
窗口去重——窗口内同键重复查询【仍走完整检测并正常应答】（服务行为
不变，绝不能因去重丢应答），仅 query_stats.record 跳过（计数消解）。

参数：
  - query_dedup_window_s：窗口秒数（默认 3.0；0=禁用去重）。
    依据：Windows 转发器重试发生在首次超时后立即（3~4s 内），
    3s 窗口覆盖重发全程；
  - 容量上限 10 万条（LRU 淘汰，约 200B/条 → 20MB 内存上限），
    超容量淘汰最旧键（极端流量下窗口精度轻微退化，可接受）。

误伤评估：真实用户 3 秒内同 client_ip+域名+qtype 重复查询的合法
场景极少（stub resolver 对同一域名的重复查询通常间隔 ≥5s；应用层
短间隔轮询属极少数且仅少计 1~2 次，不影响拦截/放行行为本身）。

线程模型：检测主流程在线程池 run_in_executor 并发调用，锁内仅
dict 读写（O(1)），微秒级不构成瓶颈。

注意：本模块只消解【计数】，不做请求拦截/应答复用——检测路径
照常执行（缓存自己会命中），应答独立构造原样返回。
"""

import threading
import time
from collections import OrderedDict

from config import CONFIG

# LRU 容量上限（条）。防内存无限增长；10 万条足够覆盖 3s 窗口内
# 的真实重发键集合（10 万终端 × 3s 窗口内重发键密度远小于此）。
_MAX_SIZE = 100_000

_LOCK = threading.Lock()
_SEEN: OrderedDict[str, float] = OrderedDict()

# 观测计数（进程生命周期累计）：消解掉的重复查询次数
STATS = {"deduped": 0, "passed": 0}


def _window() -> float:
    """窗口秒数（每次读配置，支持运行时热调；<=0 禁用）。"""
    try:
        return float(CONFIG.query_dedup_window_s)
    except (TypeError, ValueError, AttributeError):
        return 3.0


def _is_dup(key: str) -> bool:
    """键是否在窗口内出现过（并记录本次时间戳）。

    命中窗口 → True（重复，调用方跳过计数）；
    未命中/已过期/禁用 → False（首次，调用方正常计数）。
    无论返回什么，都把当前时间戳写入（重置窗口起点）。
    """
    win = _window()
    if win <= 0:                       # 禁用：永不判重
        return False
    now = time.monotonic()
    with _LOCK:
        prev = _SEEN.get(key)
        _SEEN[key] = now               # 记录/重置窗口起点
        _SEEN.move_to_end(key)
        if len(_SEEN) > _MAX_SIZE:     # LRU 淘汰最旧
            _SEEN.popitem(last=False)
        if prev is not None and (now - prev) < win:
            return True
        return False


def check_and_count(client_ip: str, domain: str, qtype) -> bool:
    """process_query 入口调用：返回是否应跳过 query_stats.record。

    返回 True = 窗口内重复（跳过计数，检测照常）；
    返回 False = 首次/窗口外（正常计数）。
    """
    key = (client_ip or "-") + "|" + (domain or "") + "|" + str(qtype)
    dup = _is_dup(key)
    with _LOCK:
        if dup:
            STATS["deduped"] += 1
        else:
            STATS["passed"] += 1
    return dup


def stats() -> dict:
    """观测快照（诊断用：消解了多少重发）。"""
    with _LOCK:
        return {
            "window_s": _window(),
            "entries": len(_SEEN),
            "deduped": STATS["deduped"],
            "passed": STATS["passed"],
        }


def reset() -> None:
    """复位（测试用）。"""
    with _LOCK:
        _SEEN.clear()
        STATS["deduped"] = 0
        STATS["passed"] = 0
