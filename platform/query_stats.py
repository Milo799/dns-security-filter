"""DNS 查询量统计（Task #161）——"今日请求"口径修正。

问题（生产 2026-09-03 观察）：/api/status 的 today_total =
intercepts + removes + allows，其中 allows 仅在 allow_log_enabled 开启
且采样命中时才有日志行——生产默认关闭放行日志，今日请求数显示值
≈ 拦截数（严重低估，实际放行占 95%+）。

方案：DNS 检测进程内存计数（零 DB 写、纳秒级原子加），后台线程
周期 UPSERT 到 dns_query_stats 表（本地日期一行，进程重启后从表恢复
当日基数），/api/status 优先读统计表：
  - today_total = total（每条进入 process_query 的查询都计，含
    detection_enabled=false 直通的——那也是"请求"）
  - intercept / remove_ip / allow 三分类与 filter_log 的 action 口径
    一致（total = 三者之和，白名单放行也计 allow）
  - 周期落库默认 5s：Web 侧读数延迟 ≤5s，事故时最多丢 5s 计数

跨进程说明：统计在 DNS 进程内累计（真正处理查询的进程）；Web 进程
只读表。双进程部署天然工作，无需跨进程同步。
"""

import logging
import threading
import time
from datetime import date

from app.db import db_cursor

logger = logging.getLogger("platform.query_stats")

# 落库周期（秒）。5s：读数延迟可忽略，单表单行 UPSERT 无锁竞争压力。
FLUSH_INTERVAL_S = 5

_LOCK = threading.Lock()
_STOP = threading.Event()
_THREAD = None

# 进程内当日计数（date 变更时重置并落库昨日尾部值）
_LOCAL = {
    "date": None,          # 当前计数归属日（date.isoformat）
    "total": 0,
    "intercept": 0,
    "remove_ip": 0,
    "allow": 0,
}


def _today() -> str:
    return date.today().isoformat()


def _ensure_loaded() -> None:
    """进程启动/日期变更时从表恢复当日基数（幂等，锁内调用）。"""
    today = _today()
    if _LOCAL["date"] == today:
        return
    if _LOCAL["date"] is not None:
        # 日期翻转：先把昨日计数落库再重置（跨午夜批次）
        _flush_locked(_LOCAL["date"])
    _LOCAL.update(date=today, total=0, intercept=0, remove_ip=0, allow=0)
    # 恢复当日基数（进程重启场景：当日已跑的量不丢）
    try:
        with db_cursor() as cur:
            cur.execute(
                "SELECT total, intercept, remove_ip, allow "
                "FROM dns_query_stats WHERE date=?", (today,))
            row = cur.fetchone()
        if row:
            _LOCAL.update(total=row["total"], intercept=row["intercept"],
                          remove_ip=row["remove_ip"], allow=row["allow"])
            logger.info("查询统计已从表恢复当日基数: total=%d", row["total"])
    except Exception:
        # 表不存在（首次运行，schema 尚未建）等：静默，等 flush 再建
        pass


def record(action: str) -> None:
    """process_query 出口调用：按 action 分类计数（action 口径与
    filter_log 一致；'allow' 含白名单放行/检测放行/直通放行）。

    线程模型：检测主流程在 executor 线程并发调用，锁内仅整型加法。
    """
    with _LOCK:
        _ensure_loaded()
        _LOCAL["total"] += 1
        if action in ("intercept", "remove_ip", "allow"):
            _LOCAL[action] += 1
        # else：未知 action 只进 total（防御：不丢总量）


def _flush_locked(day: str) -> None:
    """把 _LOCAL 计数 UPSERT 到表（锁内调用，DB 操作也在锁内——
    flush 周期 5s 一次，锁持有微秒级，检测路径不被阻塞；SQLite 写锁
    竞争见 log_writer 的削峰设计，本表单行写几乎无竞争）。"""
    try:
        with db_cursor() as cur:
            cur.execute(
                """INSERT INTO dns_query_stats
                     (date, total, intercept, remove_ip, allow, updated_at)
                   VALUES (?, ?, ?, ?, ?, datetime('now','localtime'))
                   ON CONFLICT(date) DO UPDATE SET
                     total=excluded.total,
                     intercept=excluded.intercept,
                     remove_ip=excluded.remove_ip,
                     allow=excluded.allow,
                     updated_at=datetime('now','localtime')""",
                (day, _LOCAL["total"], _LOCAL["intercept"],
                 _LOCAL["remove_ip"], _LOCAL["allow"]))
    except Exception as e:
        # 落库失败不致命：内存计数继续，下轮重试
        logger.warning("查询统计落库失败（下轮重试）: %s", e)


def flush_once() -> None:
    """立即落库一次（测试/手动触发用）。"""
    with _LOCK:
        _ensure_loaded()
        _flush_locked(_LOCAL["date"])


def today_snapshot() -> dict:
    """当日计数快照（/api/status 优先数据源）。

    Web 进程读的是表（另一进程的 DNS 计数），本地 _LOCAL 仅供
    DNS 进程自身调试——接口层读表（见 routers/config.py）。
    """
    with _LOCK:
        _ensure_loaded()
        return {
            "date": _LOCAL["date"],
            "total": _LOCAL["total"],
            "intercept": _LOCAL["intercept"],
            "remove_ip": _LOCAL["remove_ip"],
            "allow": _LOCAL["allow"],
        }


def read_today_from_db() -> dict | None:
    """从表读当日统计（Web 进程用；无行返回 None）。"""
    try:
        with db_cursor() as cur:
            cur.execute(
                "SELECT date, total, intercept, remove_ip, allow "
                "FROM dns_query_stats WHERE date=?", (_today(),))
            row = cur.fetchone()
        return dict(row) if row else None
    except Exception:
        return None


def _loop() -> None:
    while not _STOP.wait(FLUSH_INTERVAL_S):
        try:
            flush_once()
        except Exception:
            logger.exception("查询统计 flush 轮次异常（忽略，下轮重试）")


def start() -> None:
    """启动后台落库线程（DNS 进程入口调用，幂等）。"""
    global _THREAD
    if _THREAD is not None and _THREAD.is_alive():
        return
    _STOP.clear()
    with _LOCK:
        _ensure_loaded()
    _THREAD = threading.Thread(target=_loop, name="query-stats", daemon=True)
    _THREAD.start()
    logger.info("查询统计线程已启动（周期 %ds）", FLUSH_INTERVAL_S)


def stop() -> None:
    """停止并落尾数（测试隔离用）。"""
    _STOP.set()
    if _THREAD is not None:
        _THREAD.join(timeout=5)
    try:
        flush_once()
    except Exception:
        pass


def reset() -> None:
    """复位内存计数（测试用；不动表）。"""
    with _LOCK:
        _LOCAL.update(date=None, total=0, intercept=0, remove_ip=0, allow=0)
