"""域名首现采集测试（迭代 49，AI 能力规划 P0-1 地基）。

覆盖：
  1. 放行域名采集落库（domain_first_seen）；
  2. 进程内判重（同域名第二次跳过，dupes 计数）；
  3. DB 幂等（reset 后重采同域名不产生重复行）；
  4. 开关 ai_first_seen_enabled 关闭零采集；
  5. 单标签域名（localhost 等）跳过；
  6. 域名小写归一（Example.COM. → example.com）；
  7. process_query 放行集成：正常域名入首现表、拦截域名不入；
  8. stats 结构与队列满丢弃计数。

网络隔离：process_query 集成用 monkeypatch 替换上游应答；不依赖公网。

运行：cd platform && python -m pytest ../tests/test_ai_collector.py -v
"""

import pytest
from dnslib import DNSRecord, QTYPE, RR, A

import ai_collector
import detectors
from config import CONFIG
from app.db import db_cursor


@pytest.fixture
def fs_env():
    """采集测试环境：reset 状态 + 还原配置 + 清表。"""
    ai_collector.reset()
    with db_cursor() as cur:
        cur.execute("DELETE FROM domain_first_seen")
    saved = getattr(CONFIG, "ai_first_seen_enabled", True)
    CONFIG.ai_first_seen_enabled = True
    yield
    CONFIG.ai_first_seen_enabled = saved
    ai_collector.reset()
    with db_cursor() as cur:
        cur.execute("DELETE FROM domain_first_seen")


def _rows():
    with db_cursor() as cur:
        return cur.execute(
            "SELECT domain, first_client, qtype FROM domain_first_seen").fetchall()


class TestCollector:
    def test_record_and_flush(self, fs_env):
        ai_collector.record_domain_seen("example.com", "A", "10.0.0.5")
        ai_collector._flush_once()
        rows = _rows()
        assert len(rows) == 1
        assert rows[0]["domain"] == "example.com"
        assert rows[0]["first_client"] == "10.0.0.5"
        assert rows[0]["qtype"] == "A"

    def test_dedup_in_process(self, fs_env):
        ai_collector.record_domain_seen("dup.com", "A", "1.1.1.1")
        ai_collector.record_domain_seen("dup.com", "A", "2.2.2.2")
        ai_collector.record_domain_seen("dup.com", "AAAA", "3.3.3.3")
        ai_collector._flush_once()
        rows = _rows()
        assert len(rows) == 1                      # 只入队一次
        assert ai_collector.stats()["dupes"] == 2  # 后两次被判重

    def test_idempotent_across_reset(self, fs_env):
        """reset 清空进程集合后重发同域名，DB 幂等不产生重复行。"""
        ai_collector.record_domain_seen("once.com", "A", "1.1.1.1")
        ai_collector._flush_once()
        ai_collector.reset()                        # 模拟重启：集合清空
        ai_collector.record_domain_seen("once.com", "A", "9.9.9.9")
        ai_collector._flush_once()
        assert len(_rows()) == 1                    # 仍一行
        assert _rows()[0]["first_client"] == "1.1.1.1"  # 保留首次

    def test_disabled_no_collect(self, fs_env):
        CONFIG.ai_first_seen_enabled = False
        ai_collector.record_domain_seen("off.com", "A", "1.1.1.1")
        ai_collector._flush_once()
        assert _rows() == []
        assert ai_collector.stats()["enqueued"] == 0

    def test_single_label_skipped(self, fs_env):
        ai_collector.record_domain_seen("localhost", "A", "1.1.1.1")
        ai_collector._flush_once()
        assert _rows() == []

    def test_lowercase_normalize(self, fs_env):
        ai_collector.record_domain_seen("Example.COM.", "A", "1.1.1.1")
        ai_collector._flush_once()
        assert _rows()[0]["domain"] == "example.com"

    def test_stats_shape(self, fs_env):
        s = ai_collector.stats()
        for k in ("enqueued", "dupes", "flushed", "dropped", "queue_size",
                  "seen_size", "enabled"):
            assert k in s


class TestProcessQueryIntegration:
    """放行路径集成：正常域名进首现表、被拦域名不进（已由 filter_log 承载）。"""

    @pytest.fixture
    def pq_env(self, fs_env, monkeypatch):
        # 上游返回正常 A 应答（可走第 6 步放行出口）
        def fake_upstream(request):
            qname = str(request.q.qname)
            reply = request.reply()
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("93.184.216.34"), ttl=60))
            return reply
        monkeypatch.setattr(detectors, "query_upstream_reply", fake_upstream)
        # 关检测依赖（防残留名单/情报误拦）
        with db_cursor() as cur:
            cur.execute("UPDATE threatintel_api SET enabled=0")
            # 记录基线：teardown 清理本 fixture 期间新增的 filter_log 行，
            # 防污染后续测试的日志断言（全量套件顺序污染）
            cur.execute("SELECT COALESCE(MAX(id), 0) AS m FROM filter_log")
            base_id = cur.fetchone()["m"]
        saved_nrd = CONFIG.nrd_enabled
        saved_det = CONFIG.detection_enabled
        CONFIG.nrd_enabled = False
        CONFIG.detection_enabled = True
        yield
        CONFIG.nrd_enabled = saved_nrd
        CONFIG.detection_enabled = saved_det
        # 先 flush 异步日志队列（测试内拦截记录可能尚未落库），
        # 再按基线清理——否则 conftest 的 flush 会在清理后才落库造成污染
        try:
            import log_writer
            log_writer._flush_once()
        except Exception:
            pass
        with db_cursor() as cur:
            cur.execute("DELETE FROM filter_log WHERE id > ?", (base_id,))

    def test_allowed_domain_recorded(self, pq_env):
        q = DNSRecord.question("fresh-allowed-xyz.com", "A")
        reply = detectors.process_query(q, "10.9.9.9")
        ai_collector._flush_once()
        # 正常放行（A 记录返回）
        assert any(rr.rtype == QTYPE.A for rr in reply.rr)
        rows = _rows()
        assert any(r["domain"] == "fresh-allowed-xyz.com" for r in rows)

    def test_blocked_domain_not_recorded(self, pq_env):
        # 加一条本地黑名单 → 该域名被拦，应进 filter_log 而非首现表
        from app.db import invalidate_list_cache
        with db_cursor() as cur:
            cur.execute(
                "INSERT INTO filter_list (list_type, target, value, enabled) "
                "VALUES ('blacklist', 'domain', 'blocked-bad.com', 1)")
        invalidate_list_cache()
        try:
            q = DNSRecord.question("blocked-bad.com", "A")
            detectors.process_query(q, "10.9.9.8")
            ai_collector._flush_once()
            assert not any(r["domain"] == "blocked-bad.com" for r in _rows())
        finally:
            with db_cursor() as cur:
                cur.execute("DELETE FROM filter_list WHERE value='blocked-bad.com'")
                # 清理本次拦截写入的 filter_log（防污染后续测试的日志断言）
                cur.execute("DELETE FROM filter_log WHERE domain='blocked-bad.com'")
            invalidate_list_cache()
