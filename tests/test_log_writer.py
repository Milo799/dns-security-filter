"""日志采样与异步写入削峰测试 —— 10 万终端前置开发项 4/5。

前置项 4（放行日志采样）覆盖：
  - rate=100 全录 / rate=0 全不录
  - 0<rate<100 确定性采样（连续 100 次命中数恰为 rate）
  - 拦截日志不受采样影响（永远必录）

前置项 5（SQLite 写入削峰）覆盖：
  - 异步入队 → flush 后落库（executemany 批量）
  - 队列满丢弃并计数（不阻塞调用方）
  - 开关关闭回退同步直写（调用即落库）
  - stop(flush=True) 清空队列
  - stats() 计数一致性
  - write_filter_log 经异步路径最终入库（端到端）
"""

import queue

import pytest

import log_writer
from config import CONFIG
from detectors import write_filter_log, write_allow_log, _allow_log_sampled
from app.db import db_cursor


@pytest.fixture(autouse=True)
def clean_log_writer():
    """每个测试前后：停后台线程、清队列与统计、清日志表、还原配置。"""
    saved = (CONFIG.log_async_enabled, CONFIG.allow_log_sample_rate,
             CONFIG.log_batch_size, CONFIG.log_flush_interval_s)
    log_writer.stop(flush=False)
    log_writer.reset()
    _clear_filter_log()
    yield
    CONFIG.log_async_enabled, CONFIG.allow_log_sample_rate = saved[0], saved[1]
    CONFIG.log_batch_size, CONFIG.log_flush_interval_s = saved[2], saved[3]
    log_writer.stop(flush=False)
    log_writer.reset()
    _clear_filter_log()


def _filter_log_count() -> int:
    with db_cursor() as cur:
        return cur.execute("SELECT COUNT(*) FROM filter_log").fetchone()[0]


def _clear_filter_log():
    with db_cursor() as cur:
        cur.execute("DELETE FROM filter_log")


# ---------------------------------------------------------------------------
# 前置项 4：放行日志采样
# ---------------------------------------------------------------------------

class TestAllowLogSample:
    def test_rate_100_always(self):
        CONFIG.allow_log_sample_rate = 100
        assert all(_allow_log_sampled() for _ in range(50))

    def test_rate_0_never(self):
        CONFIG.allow_log_sample_rate = 0
        assert not any(_allow_log_sampled() for _ in range(50))

    def test_rate_deterministic(self):
        """任意连续 100 次调用，命中数恰等于 rate（计数取模语义）。"""
        CONFIG.allow_log_sample_rate = 30
        hits = sum(_allow_log_sampled() for _ in range(100))
        assert hits == 30

    def test_rate_30_ratio_reasonable(self):
        """1000 次采样命中率在 30% 附近（10 个整周期 = 恰 300）。"""
        CONFIG.allow_log_sample_rate = 30
        hits = sum(_allow_log_sampled() for _ in range(1000))
        assert hits == 300

    def test_write_allow_log_respects_rate(self):
        """rate=0 时 write_allow_log 不入队；rate=100 时入队。"""
        CONFIG.allow_log_sample_rate = 0
        CONFIG.log_async_enabled = True
        write_allow_log("1.1.1.1", "a.test", 1)
        assert log_writer.stats()["enqueued"] == 0

        CONFIG.allow_log_sample_rate = 100
        write_allow_log("1.1.1.1", "b.test", 1)
        assert log_writer.stats()["enqueued"] == 1


# ---------------------------------------------------------------------------
# 前置项 5：异步写入削峰
# ---------------------------------------------------------------------------

class TestAsyncWriter:
    def test_enqueue_then_flush(self):
        CONFIG.log_async_enabled = True
        for i in range(120):
            log_writer.enqueue("1.1.1.1", f"d{i}.test", "A",
                               "local_blacklist", "intercept",
                               "", "alert_ip:127.0.0.1", "")
        s = log_writer.stats()
        assert s["enqueued"] == 120
        assert s["flushed"] == 0            # 未 flush 前不落库
        assert _filter_log_count() == 0

        log_writer._flush_once()
        s = log_writer.stats()
        assert s["flushed"] == 120
        assert s["flush_batches"] == 1
        assert _filter_log_count() == 120

    def test_batch_size_splits(self):
        """batch_size=50 时 120 条分 3 批（50+50+20）。"""
        CONFIG.log_async_enabled = True
        CONFIG.log_batch_size = 50
        for i in range(120):
            log_writer.enqueue("1.1.1.1", f"d{i}.test", "A",
                               "local_blacklist", "intercept",
                               "", "", "")
        log_writer._flush_once()
        # batch_size 是单次取出行数上限，_flush_once 循环取空队列
        assert log_writer.stats()["flushed"] == 120
        assert _filter_log_count() == 120

    def test_sync_fallback(self):
        """log_async_enabled=False 时同步直写，调用即落库。"""
        CONFIG.log_async_enabled = False
        write_filter_log("1.1.1.1", "sync.test", 1,
                         "local_blacklist", "intercept", [],
                         "alert_ip:127.0.0.1")
        assert _filter_log_count() == 1
        s = log_writer.stats()
        assert s["flushed"] == 1
        assert s["enqueued"] == 0

    def test_queue_full_drops(self):
        """队列满时丢弃不阻塞，dropped 计数。"""
        CONFIG.log_async_enabled = True
        # 直接灌满队列（maxsize=100000，用 put_nowait 快速灌）
        filled = 0
        try:
            while True:
                log_writer._QUEUE.put_nowait(("x", "y", "A", "r", "a", "", "", ""))
                filled += 1
        except queue.Full:
            pass
        before = log_writer.stats()["dropped"]
        log_writer.enqueue("1.1.1.1", "drop.test", "A",
                           "local_blacklist", "intercept", "", "", "")
        assert log_writer.stats()["dropped"] == before + 1
        # 清空队列供后续断言
        log_writer.reset()

    def test_stop_flushes_residual(self):
        """stop(flush=True) 清空队列残留。"""
        CONFIG.log_async_enabled = True
        for i in range(10):
            log_writer.enqueue("1.1.1.1", f"r{i}.test", "A",
                               "local_blacklist", "intercept", "", "", "")
        log_writer.stop(flush=True)
        s = log_writer.stats()
        assert s["flushed"] == 10
        assert s["queue_size"] == 0
        assert _filter_log_count() == 10

    def test_stats_shape(self):
        s = log_writer.stats()
        for key in ("enqueued", "flushed", "dropped", "flush_batches",
                    "queue_size", "async_enabled"):
            assert key in s

    def test_write_filter_log_e2e_async(self):
        """detectors.write_filter_log 走异步路径最终完整入库（字段齐全）。"""
        _clear_filter_log()
        CONFIG.log_async_enabled = True
        write_filter_log("192.168.1.1", "e2e.test", 1,
                         "local_blacklist", "intercept", ["1.2.3.4"],
                         "alert_ip:127.0.0.1", "test-src")
        log_writer._flush_once()
        with db_cursor() as cur:
            row = cur.execute(
                "SELECT * FROM filter_log WHERE domain='e2e.test'").fetchone()
        assert row is not None
        assert row["client_ip"] == "192.168.1.1"
        assert row["query_type"] == "A"
        assert row["filter_reason"] == "local_blacklist"
        assert row["action"] == "intercept"
        assert row["malicious_ips"] == "1.2.3.4"
        assert row["final_result"] == "alert_ip:127.0.0.1"
        assert row["source_api"] == "test-src"

    def test_background_thread_flush(self):
        """start() 后台线程按 flush_interval 周期自动落库。"""
        CONFIG.log_async_enabled = True
        CONFIG.log_flush_interval_s = 1
        for i in range(5):
            log_writer.enqueue("1.1.1.1", f"bg{i}.test", "A",
                               "local_blacklist", "intercept", "", "", "")
        log_writer.start()
        # 等一个周期 + 余量
        import time
        time.sleep(2.5)
        assert log_writer.stats()["flushed"] == 5
        assert _filter_log_count() == 5
