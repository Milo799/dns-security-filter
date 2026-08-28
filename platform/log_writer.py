"""过滤日志异步批量写入（10 万终端前置开发项 5：SQLite 写入削峰）。

背景（2026-08-28 压测实证）：检测线程内同步逐条 INSERT filter_log，
高 QPS 下 20 线程池全部停在 write_filter_log 的写锁上，平台吞吐
饱和在 ~400 QPS——写日志把检测线程拖死。

方案：内存队列 + 后台单线程批量 flush。
  - write_filter_log / write_allow_log 改为只入队（微秒级，不阻塞检测线程）
  - 后台 daemon 线程每 flush_interval_s（默认 2s）或队列达 batch_size
    时 executemany 批量入库（SQLite 单写者只与后台线程竞争，锁窗口极短）
  - 队列满（max_queue，默认 10 万条）时丢弃并计数——日志削峰属可损语义，
    丢日志优于拖死检测；丢弃计数暴露在 stats() 供告警
  - 优雅关闭：atexit flush 残留，防进程退出丢尾批
  - 开关 log_async_enabled（默认开）：关闭时回退同步直写（零行为变更，
    排障用）

配置项（system_config 热生效）：
  log_async_enabled     异步写入开关（默认 1）
  log_flush_interval_s  flush 间隔秒（1~60，默认 2）
  log_batch_size        批量上限条（100~50000，默认 500）
"""

import atexit
import logging
import queue
import threading
import time

from config import CONFIG
from app.db import db_cursor

logger = logging.getLogger("platform.log_writer")

# ---------------------------------------------------------------------------
# 队列与统计
# ---------------------------------------------------------------------------

_QUEUE: "queue.Queue[tuple]" = queue.Queue(maxsize=100_000)
_STATS = {
    "enqueued": 0,        # 累计入队
    "flushed": 0,         # 累计落库
    "dropped": 0,         # 队列满丢弃
    "flush_batches": 0,   # flush 次数
    "last_flush_at": 0.0, # 最近 flush 的 monotonic 时间
}
_STATS_LOCK = threading.Lock()

_INSERT_SQL = """INSERT INTO filter_log
   (client_ip, domain, query_type, filter_reason, action,
    malicious_ips, final_result, source_api)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?)"""


def enqueue(client_ip: str, domain: str, qtype_name: str, reason: str,
            action: str, malicious_ips: str, final_result: str,
            source_api: str) -> None:
    """检测线程调用：入队或（开关关闭/队列满时）按策略处理。"""
    row = (client_ip, domain, qtype_name, reason, action,
           malicious_ips, final_result, source_api)
    if not CONFIG.log_async_enabled:
        _write_sync([row])
        return
    try:
        _QUEUE.put_nowait(row)
        with _STATS_LOCK:
            _STATS["enqueued"] += 1
    except queue.Full:
        # 队列满：丢弃保检测线程（可损语义），计数供告警
        with _STATS_LOCK:
            _STATS["dropped"] += 1


def _write_sync(rows: list[tuple]) -> None:
    """同步直写（开关关闭时的回退路径 / flush 线程实际落库）。"""
    with db_cursor() as cur:
        cur.executemany(_INSERT_SQL, rows)
    with _STATS_LOCK:
        _STATS["flushed"] += len(rows)
        _STATS["flush_batches"] += 1
        _STATS["last_flush_at"] = time.monotonic()


# ---------------------------------------------------------------------------
# 后台 flush 线程
# ---------------------------------------------------------------------------

_STOP = threading.Event()


def _flush_once() -> None:
    """取空当前队列并批量落库（单次，供线程与测试复用）。

    batch_size 是单条 executemany 上限：超出部分循环分批，
    保证一次调用清空队列。
    """
    while True:
        rows = []
        while len(rows) < max(1, CONFIG.log_batch_size):
            try:
                rows.append(_QUEUE.get_nowait())
            except queue.Empty:
                break
        if not rows:
            return
        _write_sync(rows)


def _flush_loop() -> None:
    """后台线程主循环：按间隔或停止信号 flush。"""
    while not _STOP.is_set():
        interval = max(1, CONFIG.log_flush_interval_s)
        _STOP.wait(interval)
        try:
            _flush_once()
        except Exception:
            # 落库失败（如 DB 短暂锁死）不能让线程退出；
            # 数据留在队列里下轮重试——但队列只出不进的行已取出，
            # 失败即丢，计数已 _write_sync 前置语义约束，此处记日志
            logger.exception("异步日志 flush 失败（本批丢弃）")


def start() -> None:
    """启动后台 flush 线程（进程入口调用，幂等）。

    先清停止标志——stop() 后重启（测试隔离/服务复用）才能正常跑循环。
    """
    global _THREAD
    if _THREAD is not None and _THREAD.is_alive():
        return
    _STOP.clear()
    _THREAD = threading.Thread(target=_flush_loop, name="log-flusher",
                               daemon=True)
    _THREAD.start()
    logger.info("异步日志写入线程已启动（间隔 %ss，批量 %s）",
                CONFIG.log_flush_interval_s, CONFIG.log_batch_size)


def stop(flush: bool = True) -> None:
    """停止后台线程；flush=True 时先清空队列（测试与优雅退出用）。"""
    _STOP.set()
    if _THREAD is not None:
        _THREAD.join(timeout=10)
    if flush:
        try:
            _flush_once()
        except Exception:
            logger.exception("退出 flush 失败")


def stats() -> dict:
    """队列与写入统计（运维巡检/告警：dropped>0 说明写入跟不上）。"""
    with _STATS_LOCK:
        s = dict(_STATS)
    s["queue_size"] = _QUEUE.qsize()
    s["async_enabled"] = bool(CONFIG.log_async_enabled)
    return s


def reset() -> None:
    """清空队列与统计（测试隔离用）。"""
    with _STATS_LOCK:
        for k in ("enqueued", "flushed", "dropped", "flush_batches"):
            _STATS[k] = 0
        _STATS["last_flush_at"] = 0.0
    while True:
        try:
            _QUEUE.get_nowait()
        except queue.Empty:
            break


_THREAD: threading.Thread | None = None

# 优雅退出：进程结束时 flush 残留（daemon 线程不会执行 atexit 前的清理）
atexit.register(lambda: stop(flush=True))
