"""P1 生产就绪缺口补齐的测试（2026-08-31 评估后新增三项）。

覆盖：
1. api_key 落库加密（app/crypto.py + threatintel 路由接入）
2. 日志保留期自动清理（log_retention.py）
"""

import sqlite3
import time

import pytest

from conftest import CONFIG


# ===========================================================================
# 1. crypto 模块单元测试
# ===========================================================================

class TestCryptoRoundtrip:
    def test_encrypt_decrypt_roundtrip(self):
        from app.crypto import encrypt_key, decrypt_key
        cipher = encrypt_key("my-secret-api-key")
        assert cipher.startswith("enc:")
        assert "my-secret-api-key" not in cipher
        assert decrypt_key(cipher) == "my-secret-api-key"

    def test_empty_key_passthrough(self):
        from app.crypto import encrypt_key, decrypt_key
        assert encrypt_key("") == ""
        assert decrypt_key("") == ""

    def test_plaintext_compatible(self):
        """历史明文（无 enc: 前缀）原样返回——存量库平滑兼容。"""
        from app.crypto import decrypt_key
        assert decrypt_key("legacy-plaintext-key") == "legacy-plaintext-key"

    def test_encrypt_idempotent(self):
        """已是密文的值不会二次加密。"""
        from app.crypto import encrypt_key
        cipher = encrypt_key("k1")
        assert encrypt_key(cipher) == cipher

    def test_wrong_secret_returns_empty(self):
        """jwt_secret 更换后旧密文解不开 → 返回空串（不抛异常）。"""
        from app.crypto import encrypt_key, decrypt_key, _get_fernet
        import app.crypto as crypto_mod
        cipher = encrypt_key("k2")
        # 模拟换密钥：重置单例并换 secret
        old_secret = CONFIG.web.jwt_secret
        try:
            CONFIG.web.jwt_secret = "another-secret-32bytes-xxxxxxxxxxxx"
            crypto_mod._fernet = None
            assert decrypt_key(cipher) == ""
        finally:
            CONFIG.web.jwt_secret = old_secret
            crypto_mod._fernet = None


class TestCryptoMigration:
    def test_migrate_plaintext_keys(self):
        """存量明文 api_key 启动迁移：全部变 enc: 前缀，解密还原一致。"""
        from app.crypto import migrate_plaintext_keys, decrypt_key
        from app.db import db_cursor
        with db_cursor() as cur:
            cur.execute("DELETE FROM threatintel_api WHERE name LIKE 'crypto-mig-%'")
            cur.execute(
                "INSERT INTO threatintel_api (name, adapter_type, base_url,"
                " api_key, enabled, timeout_ms) VALUES "
                "('crypto-mig-a', 'http', '', 'plain-key-a', 1, 2000),"
                "('crypto-mig-b', 'http', '', '', 0, 2000)")
        migrated = migrate_plaintext_keys()
        assert migrated >= 1
        with db_cursor() as cur:
            cur.execute(
                "SELECT api_key FROM threatintel_api WHERE name='crypto-mig-a'")
            stored = cur.fetchone()["api_key"]
            cur.execute(
                "SELECT api_key FROM threatintel_api WHERE name='crypto-mig-b'")
            empty = cur.fetchone()["api_key"]
        assert stored.startswith("enc:")
        assert decrypt_key(stored) == "plain-key-a"
        assert empty == ""                     # 空 key 不动
        # 幂等：再跑一轮不再迁移
        assert migrate_plaintext_keys() == 0

    def test_api_key_router_end_to_end(self):
        """路由层：POST 创建带 Key 的源 → 落库为密文；GET 列表脱敏展示。"""
        from app.main import app
        from fastapi.testclient import TestClient
        from app.db import db_cursor
        with TestClient(app) as client:
            token = client.post("/api/auth/login",
                                json={"username": "admin",
                                      "password": CONFIG.admin_initial_password}
                                ).json()["data"]["token"]
            h = {"Authorization": f"Bearer {token}"}
            # 创建带明文 Key 的自定义源（example 是免 Key 测试适配器）
            r = client.post("/api/threatintel", headers=h, json={
                "name": "example", "adapter_type": "http",
                "base_url": "", "api_key": "router-secret-key",
                "enabled": False, "timeout_ms": 500,
            })
            assert r.status_code == 200, r.text
            with db_cursor() as cur:
                cur.execute(
                    "SELECT api_key FROM threatintel_api WHERE name='example'")
                stored = cur.fetchone()["api_key"]
            assert stored.startswith("enc:")            # 落库密文
            assert "router-secret-key" not in stored
            # 列表接口：脱敏回显（尾 4 位）
            r2 = client.get("/api/threatintel", headers=h)
            items = {i["name"]: i for i in r2.json()["data"]["items"]}
            assert items["example"]["api_key_masked"] == "●●●●●●-key"
            # 更新：传脱敏值 → 保留原密文；解密仍一致
            r3 = client.put("/api/threatintel/{id}".format(
                id=items["example"]["id"]), headers=h, json={
                "name": "example", "adapter_type": "http",
                "base_url": "", "api_key": "●●●●●●-key",
                "enabled": False, "timeout_ms": 500,
            })
            assert r3.status_code == 200
            with db_cursor() as cur:
                cur.execute(
                    "SELECT api_key FROM threatintel_api WHERE name='example'")
                assert cur.fetchone()["api_key"] == stored
            # 清理
            client.delete("/api/threatintel/{id}".format(
                id=items["example"]["id"]), headers=h)

    def test_get_enabled_adapters_decrypts(self):
        """检测链路取适配器时 Key 已解密（密文不泄漏到适配器）。"""
        from adapters import get_enabled_adapters
        from app.crypto import encrypt_key
        from app.db import db_cursor
        with db_cursor() as cur:
            cur.execute("DELETE FROM threatintel_api WHERE name='example'")
            cur.execute(
                "INSERT INTO threatintel_api (name, adapter_type, base_url,"
                " api_key, enabled, timeout_ms) VALUES "
                "('example', 'http', '', ?, 1, 500)",
                (encrypt_key("enabled-decrypted-key"),))
        try:
            adapters = get_enabled_adapters()
            ex = [a for a in adapters if a.name == "example"]
            assert ex and ex[0].api_key == "enabled-decrypted-key"
        finally:
            with db_cursor() as cur:
                cur.execute("DELETE FROM threatintel_api WHERE name='example'")


# ===========================================================================
# 2. 日志保留期清理测试
# ===========================================================================

class TestLogRetention:
    def _insert_logs(self, days_ago: float, count: int, table="filter_log"):
        """插一批指定天数的日志（直接写 timestamp 列）。"""
        from app.db import db_cursor
        ts = time.strftime("%Y-%m-%d %H:%M:%S",
                           time.localtime(time.time() - days_ago * 86400))
        with db_cursor() as cur:
            for _ in range(count):
                cur.execute(
                    f"INSERT INTO {table} (client_ip, domain, query_type,"   # noqa: S608
                    f" filter_reason, action, malicious_ips, final_result,"
                    f" source_api, timestamp)"
                    f" VALUES ('1.2.3.4', 'old.example.com', 'A', 'test',"
                    f" 'intercept', '', '', '', ?)", (ts,))

    def _count_logs(self, table="filter_log") -> int:
        from app.db import db_cursor
        with db_cursor() as cur:
            return cur.execute(f"SELECT COUNT(*) c FROM {table}").fetchone()["c"]   # noqa: S608

    def _cleanup_logs(self):
        """清掉本类测试注入的行（按唯一域名标识，避免测试间污染）。"""
        from app.db import db_cursor
        with db_cursor() as cur:
            cur.execute("DELETE FROM filter_log WHERE domain='old.example.com'")
            cur.execute("DELETE FROM audit_log WHERE 1=0")   # audit 不注入，占位保持结构

    def setup_method(self):
        self._cleanup_logs()

    def teardown_method(self):
        self._cleanup_logs()

    def test_purge_removes_expired_keeps_fresh(self):
        """过期删除、保留天数内不删。"""
        import log_retention
        old = self._count_logs()
        self._insert_logs(days_ago=100, count=3)     # 100 天前（>90 默认）
        self._insert_logs(days_ago=1, count=2)       # 1 天前（保留）
        assert self._count_logs() == old + 5
        deleted = log_retention.purge_once()
        assert deleted >= 3
        assert self._count_logs() == old + 2

    def test_purge_respects_retention_config(self):
        """log_retention_days 热生效：调大天数后原过期行保留。"""
        import log_retention
        self._insert_logs(days_ago=100, count=2)
        old_days = CONFIG.log_retention_days
        try:
            CONFIG.log_retention_days = 365          # 365 天内不删
            before = self._count_logs()
            log_retention.purge_once()
            assert self._count_logs() == before
        finally:
            CONFIG.log_retention_days = old_days

    def test_purge_handles_batches(self):
        """超过单批上限的过期数据分批删完（BATCH_SIZE 压小验证）。"""
        import log_retention
        self._insert_logs(days_ago=200, count=25)
        orig_batch = log_retention.BATCH_SIZE
        orig_pause = log_retention.BATCH_PAUSE_S
        try:
            log_retention.BATCH_SIZE = 10            # 25 行 → 3 批
            log_retention.BATCH_PAUSE_S = 0          # 测试不等待
            before = self._count_logs()
            log_retention.purge_once()
            assert self._count_logs() == before - 25
        finally:
            log_retention.BATCH_SIZE = orig_batch
            log_retention.BATCH_PAUSE_S = orig_pause

    def test_stats_counts(self):
        import log_retention
        self._insert_logs(days_ago=150, count=1)
        base = log_retention.stats()["total_runs"]
        log_retention.purge_once()
        s = log_retention.stats()
        assert s["total_runs"] == base + 1
        assert s["last_run_at"] > 0
        assert s["last_deleted"] >= 1

    def test_start_stop_thread(self):
        """start() 幂等 + stop() 可停（不真等 6 小时周期，仅验证线程语义）。"""
        import log_retention
        log_retention.start()
        t1 = log_retention._THREAD
        assert t1 is not None and t1.is_alive()
        log_retention.start()                       # 幂等：同一线程
        assert log_retention._THREAD is t1
        log_retention.stop()
        assert not t1.is_alive()
