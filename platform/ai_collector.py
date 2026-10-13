"""域名首现采集（AI 能力规划 §4 地基：行为分析的数据源）。

定位与红线：
  - **只读旁路**：本模块只在"全正常放行"出口（detectors.process_query 第 6 步）
    采集放行域名，绝不参与拦截判定——拦截域名已由 filter_log 承载，本表只补
    "放行域名的首现时刻"这一缺失信号；
  - **热路径零阻塞**：检测线程只做进程内 set 判重（O(1)）+ 队列 put_nowait，
    DB 写由后台单线程批量完成（复刻 log_writer 削峰模式，压测实证的最优解）；
  - **幂等**：INSERT OR IGNORE + domain 主键，重复域名自动忽略，重启后 set
    重建时重发也由 DB 幂等兜底。

数据语义：
  domain_first_seen 每域名仅一行（首现时刻 + 首个客户端 + 查询类型）——
  DGA 检测的"新域名"信号、客户端"新域名尝试率"指标、威胁狩猎的时间起点。

开关：ai_first_seen_enabled（system_config 热生效，默认开）。
"""

import atexit
import logging
import queue
import threading
import time

from config import CONFIG

logger = logging.getLogger("platform.ai_collector")

# ---------------------------------------------------------------------------
# 队列与统计（与 log_writer 同款口径）
# ---------------------------------------------------------------------------

_QUEUE: "queue.Queue[tuple]" = queue.Queue(maxsize=100_000)
_STATS = {
    "enqueued": 0,        # 累计入队（新域名）
    "dupes": 0,           # 进程内判重命中（已见域名，直接跳过）
    "flushed": 0,         # 累计落库尝试
    "dropped": 0,         # 队列满丢弃
    "flush_batches": 0,
    "last_flush_at": 0.0,
}
_STATS_LOCK = threading.Lock()

# 进程内已见集合：精确判重（无 bloom 假阳性）。域名数万级/天，内存可控。
_SEEN: set[str] = set()
_SEEN_LOCK = threading.Lock()
_SEEN_MAX = 300_000      # 上限防内存膨胀；超出清空重建（DB 幂等兜底，极少触发）

_INSERT_SQL = ("INSERT OR IGNORE INTO domain_first_seen "
               "(domain, first_client, qtype) VALUES (?, ?, ?)")


def record_domain_seen(domain: str, qtype_name: str, client_ip: str = "") -> None:
    """检测线程调用：判重后入队（微秒级，不阻塞）。

    仅放行路径调用；domain 已小写无尾点由调用方保证（process_query 口径）。
    """
    if not getattr(CONFIG, "ai_first_seen_enabled", True):
        return
    d = (domain or "").rstrip(".").lower()
    if not d or "." not in d:        # 单标签域名（localhost 等）无分析价值
        return
    with _SEEN_LOCK:
        if d in _SEEN:
            with _STATS_LOCK:
                _STATS["dupes"] += 1
            return
        _SEEN.add(d)
        if len(_SEEN) > _SEEN_MAX:
            _SEEN.clear()            # 重建（DB INSERT OR IGNORE 幂等兜底）
            _SEEN.add(d)
    try:
        _QUEUE.put_nowait((d, client_ip or "", qtype_name or ""))
        with _STATS_LOCK:
            _STATS["enqueued"] += 1
    except queue.Full:
        with _STATS_LOCK:
            _STATS["dropped"] += 1


def _write_sync(rows: list[tuple]) -> None:
    from app.db import db_cursor
    with db_cursor() as cur:
        cur.executemany(_INSERT_SQL, rows)
    with _STATS_LOCK:
        _STATS["flushed"] += len(rows)
        _STATS["flush_batches"] += 1
        _STATS["last_flush_at"] = time.monotonic()


# ---------------------------------------------------------------------------
# 后台 flush 线程（复刻 log_writer 模式）
# ---------------------------------------------------------------------------

_STOP = threading.Event()
_THREAD: threading.Thread | None = None
_FLUSH_INTERVAL_S = 2
_BATCH_SIZE = 500


def _flush_once() -> None:
    """取空当前队列批量落库（单次，供线程与测试复用）。"""
    while True:
        rows = []
        while len(rows) < _BATCH_SIZE:
            try:
                rows.append(_QUEUE.get_nowait())
            except queue.Empty:
                break
        if not rows:
            return
        _write_sync(rows)


def _flush_loop() -> None:
    while not _STOP.is_set():
        _STOP.wait(_FLUSH_INTERVAL_S)
        try:
            _flush_once()
        except Exception:
            logger.exception("首现采集 flush 失败（本批丢弃）")


def start() -> None:
    """启动后台 flush 线程（进程入口调用，幂等）。"""
    global _THREAD
    if _THREAD is not None and _THREAD.is_alive():
        return
    _STOP.clear()
    _THREAD = threading.Thread(target=_flush_loop, name="ai-first-seen",
                               daemon=True)
    _THREAD.start()
    logger.info("域名首现采集线程已启动（间隔 %ss）", _FLUSH_INTERVAL_S)


def stop(flush: bool = True) -> None:
    _STOP.set()
    if _THREAD is not None:
        _THREAD.join(timeout=10)
    if flush:
        try:
            _flush_once()
        except Exception:
            logger.exception("首现采集退出 flush 失败")


def stats() -> dict:
    with _STATS_LOCK:
        s = dict(_STATS)
    s["queue_size"] = _QUEUE.qsize()
    s["seen_size"] = len(_SEEN)
    s["enabled"] = bool(getattr(CONFIG, "ai_first_seen_enabled", True))
    return s


def reset() -> None:
    """清空队列/统计/已见集合（测试隔离用）。"""
    with _STATS_LOCK:
        for k in ("enqueued", "dupes", "flushed", "dropped", "flush_batches"):
            _STATS[k] = 0
        _STATS["last_flush_at"] = 0.0
    with _SEEN_LOCK:
        _SEEN.clear()
    while True:
        try:
            _QUEUE.get_nowait()
        except queue.Empty:
            break


atexit.register(lambda: stop(flush=True))
