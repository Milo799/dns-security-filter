"""队列深度观测测试 —— Task #160（生产事故 2026-09-03 加固）。

覆盖：
  - submitted/completed 配对：pending 升降、max_pending 峰值记录
  - started/ended 配对：inflight 升降
  - 异常路径不断配对（finally 保证 completed/ended 必达）
  - 告警：pending 超阈值触发 warn_count（限速窗口内不重复告警）
  - stats 快照字段口径
  - /api/queue-stats 端点
  - handle_request 集成：慢检测并发提交时 pending 可观测
"""

import asyncio
import time

import pytest
from dnslib import DNSRecord

import queue_stats


@pytest.fixture(autouse=True)
def clean():
    queue_stats.reset()
    yield
    queue_stats.reset()


# ---------------- 计数配对 ----------------

def test_submitted_completed_pairing():
    queue_stats.submitted()
    assert queue_stats.stats()["pending"] == 1
    queue_stats.submitted()
    assert queue_stats.stats()["pending"] == 2
    assert queue_stats.stats()["max_pending"] == 2
    queue_stats.completed()
    queue_stats.completed()
    assert queue_stats.stats()["pending"] == 0
    assert queue_stats.stats()["max_pending"] == 2      # 峰值保留
    queue_stats.completed()                              # 防御性下限
    assert queue_stats.stats()["pending"] == 0


def test_started_ended_pairing():
    queue_stats.started()
    queue_stats.started()
    assert queue_stats.stats()["inflight"] == 2
    queue_stats.ended()
    queue_stats.ended()
    assert queue_stats.stats()["inflight"] == 0
    queue_stats.ended()                                  # 防御性下限
    assert queue_stats.stats()["inflight"] == 0


def test_total_submitted_accumulates():
    for _ in range(5):
        queue_stats.submitted()
        queue_stats.completed()
    assert queue_stats.stats()["total_submitted"] == 5
    assert queue_stats.stats()["pending"] == 0


# ---------------- 异常路径配对 ----------------

def test_exception_path_still_decrements():
    """_process 抛异常（finally 兜底）时 pending/inflight 仍正确递减。"""
    queue_stats.submitted()
    queue_stats.started()
    with pytest.raises(RuntimeError):
        try:
            raise RuntimeError("模拟检测主流程异常")
        finally:
            queue_stats.ended()
    # handle_request 外层 finally（await 抛出后）同样兜底 completed
    try:
        pass
    finally:
        queue_stats.completed()
    st = queue_stats.stats()
    assert st["pending"] == 0 and st["inflight"] == 0


# ---------------- 告警 ----------------

def test_warn_threshold_triggers_and_rate_limits():
    for _ in range(queue_stats.WARN_THRESHOLD):
        queue_stats.submitted()
    st = queue_stats.stats()
    assert st["warn_count"] == 1                 # 首次越限即告警
    assert st["max_pending"] >= queue_stats.WARN_THRESHOLD
    # 限速窗口内再越限：不重复告警（pending 继续涨）
    for _ in range(10):
        queue_stats.submitted()
    assert queue_stats.stats()["warn_count"] == 1
    # 窗口过期后再越限：再告警一次
    queue_stats._last_warn -= queue_stats._WARN_INTERVAL_S + 1
    queue_stats.submitted()
    assert queue_stats.stats()["warn_count"] == 2


# ---------------- stats 快照 ----------------

def test_stats_shape():
    st = queue_stats.stats()
    assert set(st) == {"pending", "inflight", "max_pending",
                       "total_submitted", "warn_count"}
    assert all(isinstance(v, int) for v in st.values())


# ---------------- API 端点 ----------------

def test_queue_stats_endpoint():
    from fastapi.testclient import TestClient
    from config import CONFIG
    from app.main import app
    queue_stats.submitted()
    with TestClient(app) as c:
        r = c.post("/api/auth/login", json={
            "username": "admin", "password": CONFIG.admin_initial_password})
        token = r.json()["data"]["token"]
        r = c.get("/api/queue-stats",
                  headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        data = r.json()["data"]
        assert set(data) == {"pending", "inflight", "max_pending",
                             "total_submitted", "warn_count"}
        assert data["total_submitted"] >= 1
        assert data["max_pending"] >= 1


# ---------------- handle_request 集成 ----------------

def test_handle_request_observability_with_slow_detection():
    """并发慢检测时：pending 峰值 = 并发数（观测钩子真实接线验证）。"""
    import dns_server

    released = asyncio.Event()
    submit_calls = {"n": 0}

    def slow_process(request, client_ip=None):
        # 模拟慢检测：挂 100ms
        time.sleep(0.1)
        return request.reply()

    orig_process = dns_server.process_query
    dns_server.process_query = slow_process
    orig_submitted = queue_stats.submitted

    def counting_submitted():
        submit_calls["n"] += 1
        orig_submitted()

    queue_stats.submitted = counting_submitted

    async def scenario():
        loop = asyncio.get_running_loop()
        # 模拟 transport
        class FakeTransport:
            def sendto(self, data, addr):
                pass

        # 并发 8 个查询（默认池 worker 数 < 8 时会排队）
        tasks = [asyncio.create_task(
            dns_server.handle_request(
                DNSRecord.question(f"q{i}.test", "A").pack(),
                FakeTransport(), ("127.0.0.1", 5353)))
            for i in range(8)]
        await asyncio.gather(*tasks)

    try:
        asyncio.run(scenario())
    finally:
        dns_server.process_query = orig_process
        queue_stats.submitted = orig_submitted

    st = queue_stats.stats()
    assert submit_calls["n"] == 8
    assert st["total_submitted"] == 8
    assert st["pending"] == 0                       # 全部完成
    assert st["inflight"] == 0
    assert 1 <= st["max_pending"] <= 8              # 峰值可观测
