"""日志保留期自动清理（P1-1：filter_log / audit_log 按保留天数删除）。

背景：log_retention_days 配置项全链路存在（config/seed/路由校验），
但此前无任何 DELETE 任务——生产就绪度评估（2026-08-31）发现文档
承诺"90 天自动清理"而代码未实现，filter_log/audit_log 将无限增长
直至撑爆系统盘。

设计（与 log_writer/auto_update 同风格，生产优先）：
- 后台 daemon 线程周期执行（默认每 6 小时查一次，清理间隔独立可配）；
- 每次清理按表逐个执行「分批 DELETE ... LIMIT」：
    - 单批上限 batch（默认 10000 行）防长事务：大表一次性 DELETE
      数百万行会长时间持有写锁，与检测链路/异步日志写入争锁，
      WAL 模式下 reader 不阻塞但 writer 互斥；
    - 批间 sleep 短暂停（默认 0.5s）让出写窗口；
    - DELETE ... WHERE rowid IN (SELECT rowid ... LIMIT ?) 走
      timestamp 索引子查询，避免全表扫；
- 空表/无过期行时零成本跳过；
- 任何异常只记日志绝不中断线程（与 auto_update 兜底语义一致）；
- 保留天数 log_retention_days 热生效（每轮重新读 CONFIG）；
- 清理统计暴露在 stats()（最后清理时间/累计删除行数），供运维观测。

挂载点：
- Web 进程：main.py startup（本文件 start()）
- DNS 进程：dns_server.py run_dns_server() 同样 start()——
  双进程部署时只需一个进程真正执行删除（两个进程都跑也无害：
  DELETE 幂等，SQLite 单写者串行化），这保证单进程形态
  （仅 platform-dns）也有清理能力。
"""

import logging
import threading
import time

from config import CONFIG
from app.db import db_cursor

logger = logging.getLogger("platform.log_retention")

# ---- 可调常量（保守默认，无需配置化——清理行为低频低危） ----
BATCH_SIZE = 10_000          # 单批删除上限（防长事务锁库）
BATCH_PAUSE_S = 0.5          # 批间让出写窗口
DEFAULT_INTERVAL_S = 6 * 3600    # 清理周期：6 小时

_STOP = threading.Event()
_THREAD: threading.Thread | None = None

_STATS = {
    "last_run_at": 0.0,          # 最近一轮清理的 monotonic 时刻
    "last_deleted": 0,           # 最近一轮删除总行数（两表合计）
    "total_deleted": 0,          # 累计删除行数
    "total_runs": 0,             # 累计执行轮数
}

# 目标表：filter_log 必清；audit_log 属安全审计留痕，
# 保留期同样受 log_retention_days 约束（等保场景可调大天数而非关闭）
_TABLES = ("filter_log", "audit_log")


def _retention_days() -> int:
    """读保留天数（每轮重读，热生效）；非法值回退 90。"""
    try:
        days = int(CONFIG.log_retention_days)
    except (TypeError, ValueError):
        days = 90
    return max(1, min(days, 3650))


def purge_once() -> int:
    """执行一轮清理，返回本轮删除总行数（测试可直接调用）。

    对每张目标表：分批删除 timestamp 早于 (now - retention_days)
    的行，直到无过期行。单批失败记日志继续下一表（不抛异常）。
    """
    days = _retention_days()
    cutoff = time.strftime(
        "%Y-%m-%d %H:%M:%S", time.localtime(time.time() - days * 86400))
    total = 0
    for table in _TABLES:
        deleted = 0
        try:
            while True:
                with db_cursor() as cur:
                    cur.execute(
                        f"DELETE FROM {table} WHERE rowid IN ("     # noqa: S608 白名单表名
                        f"  SELECT rowid FROM {table}"
                        f"  WHERE timestamp < ? LIMIT ?)",
                        (cutoff, BATCH_SIZE))
                    n = cur.rowcount
                deleted += n
                if n < BATCH_SIZE:
                    break
                time.sleep(BATCH_PAUSE_S)     # 让出写窗口给检测链路
        except Exception as e:
            logger.warning("清理 %s 过期日志失败：%s", table, e)
        if deleted:
            logger.info("已清理 %s 过期日志 %d 行（保留 %d 天，界限 %s）",
                        table, deleted, days, cutoff)
        total += deleted
    _STATS["last_run_at"] = time.monotonic()
    _STATS["last_deleted"] = total
    _STATS["total_deleted"] += total
    _STATS["total_runs"] += 1
    return total


def _loop() -> None:
    """后台线程主循环：启动先清一轮，此后按周期执行。"""
    while not _STOP.is_set():
        try:
            purge_once()
        except Exception:
            # purge_once 内部已兜底到表级；此处防御线程级异常
            logger.exception("日志清理轮次异常（忽略，下轮重试）")
        _STOP.wait(DEFAULT_INTERVAL_S)


def start() -> None:
    """启动后台清理线程（进程入口调用，幂等）。"""
    global _THREAD
    if _THREAD is not None and _THREAD.is_alive():
        return
    _STOP.clear()
    _THREAD = threading.Thread(target=_loop, name="log-retention",
                               daemon=True)
    _THREAD.start()
    logger.info("日志保留期清理线程已启动（周期 %ds，单批 %d 行，当前保留 %d 天）",
                DEFAULT_INTERVAL_S, BATCH_SIZE, _retention_days())


def stop() -> None:
    """停止后台线程（测试隔离用）。"""
    _STOP.set()
    if _THREAD is not None:
        _THREAD.join(timeout=5)


def stats() -> dict:
    """清理状态快照（运维观测）。"""
    return dict(_STATS)
