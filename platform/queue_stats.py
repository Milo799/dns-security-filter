"""DNS 检测线程池（run_in_executor 默认池）队列深度观测 —— Task #160。

背景（生产事故 2026-09-03）：出站超时把默认 executor（worker 数 =
CPU 核数，事故机 6 个）全部占住，新查询在队列里无限排队，事件循环
健康但全网无应答——当时唯一的手段是 py-spy dump。本模块把这个盲区
变成可观测指标：

  - dns_server.handle_request 提交 executor 前 pending+1、完成（含
    异常）后 pending-1；
  - max_pending 记录历史峰值（水位线，排障时一眼看出是否发生过堆积）；
  - 超过告警阈值（默认 100）时 journalctl 打 WARNING（含堆积提示，
    1 分钟限速防刷屏）；
  - Web 侧 GET /api/queue-stats 读快照（零开销，锁内仅纳秒级读写）。

设计约束：
  - 计数器读写全部走本模块函数，不在 dns_server 里散落裸 dict；
  - 与 log_writer/log_retention 的 stats 口径一致（dict 快照）；
  - 不做任何持久化——进程重启归零属预期（观测目标是"当下是否堆积"）。
"""

import logging
import threading
import time

logger = logging.getLogger("platform.queue_stats")

_LOCK = threading.Lock()

# 告警阈值：pending 超过此值说明 executor 已供不应求（6 worker 全忙
# 且队列积压）。默认 100 ≈ 事故形态下数十秒内的自然堆积量级，可调。
WARN_THRESHOLD = 100
_WARN_INTERVAL_S = 60        # 告警限速（秒）

_STATS = {
    "pending": 0,            # 当前已提交未完成的查询数（含执行中）
    "inflight": 0,           # 当前正在 executor 里执行的数量（≤ worker 数）
    "max_pending": 0,        # 历史峰值（进程生命周期内）
    "total_submitted": 0,    # 累计提交数
    "warn_count": 0,         # 累计告警次数
}
_last_warn = 0.0


# 钩子配对关系（防双计数）：
#   handle_request: submitted() → …… await 完成（含取消/异常）→ completed()
#   _process 内部:  started() → …… finally → ended()
# 取消发生在 worker 接活前时 started/ended 不执行，不影响 pending 口径。

def submitted() -> None:
    """handle_request 提交 executor 前调用：pending+1、total+1。"""
    global _last_warn
    warn = False
    with _LOCK:
        _STATS["pending"] += 1
        _STATS["total_submitted"] += 1
        if _STATS["pending"] > _STATS["max_pending"]:
            _STATS["max_pending"] = _STATS["pending"]
        if _STATS["pending"] >= WARN_THRESHOLD:
            now = time.monotonic()
            if now - _last_warn >= _WARN_INTERVAL_S:
                _last_warn = now
                _STATS["warn_count"] += 1
                warn = True
                pending = _STATS["pending"]
                peak = _STATS["max_pending"]
    if warn:
        logger.warning(
            "检测线程池积压告警：当前排队 %d（历史峰值 %d）——"
            "executor worker 全忙或检测链路出现慢源，请结合 "
            "py-spy dump / circuit-breaker stats 排查",
            pending, peak)


def completed() -> None:
    """任务结束（完成/异常/取消，await 返回或抛出后）调用：pending-1。"""
    with _LOCK:
        _STATS["pending"] = max(0, _STATS["pending"] - 1)


def started() -> None:
    """任务在 worker 里实际开始执行时调用：inflight+1。"""
    with _LOCK:
        _STATS["inflight"] += 1


def ended() -> None:
    """任务执行结束（_process 的 finally）调用：inflight-1。"""
    with _LOCK:
        _STATS["inflight"] = max(0, _STATS["inflight"] - 1)


def stats() -> dict:
    """队列状态快照（GET /api/queue-stats 用）。"""
    with _LOCK:
        return dict(_STATS)


def reset() -> None:
    """复位（测试用）。"""
    global _last_warn
    with _LOCK:
        for k in _STATS:
            _STATS[k] = 0
        _last_warn = 0.0
