"""初始化：默认管理员 + 默认系统配置 + 内置开源情报源（首次启动时执行）。"""

import json
import logging
import os

import bcrypt

from config import CONFIG
from app.db import get_conn

logger = logging.getLogger("platform.seed")

DEFAULT_SYSTEM_CONFIG = {
    "alert_ip": CONFIG.alert_ip,
    "alert_ttl": str(CONFIG.alert_ttl),
    "upstream_dns": CONFIG.upstream_dns,
    "fusion_strategy": CONFIG.fusion_strategy,
    "log_retention_days": str(CONFIG.log_retention_days),
    "allow_log_enabled": str(int(CONFIG.allow_log_enabled)),
    "allow_log_sample_rate": str(CONFIG.allow_log_sample_rate),
    "log_async_enabled": str(int(CONFIG.log_async_enabled)),
    "log_flush_interval_s": str(CONFIG.log_flush_interval_s),
    "log_batch_size": str(CONFIG.log_batch_size),
    "detection_enabled": str(int(CONFIG.detection_enabled)),
    "domain_cache_ttl_s": str(CONFIG.domain_cache_ttl_s),
    "domain_cache_size": str(CONFIG.domain_cache_size),
    "ip_cache_ttl_s": str(CONFIG.ip_cache_ttl_s),
    "ip_cache_size": str(CONFIG.ip_cache_size),
    "failsafe_mode": CONFIG.failsafe_mode,
    "cb_failure_threshold": str(CONFIG.cb_failure_threshold),
    "cb_open_timeout_s": str(CONFIG.cb_open_timeout_s),
    "degrade_threshold": str(CONFIG.degrade_threshold),
    "degrade_window_s": str(CONFIG.degrade_window_s),
    "threatlist_auto_update": str(int(CONFIG.threatlist_auto_update)),
    "threatlist_auto_interval_hours": str(CONFIG.threatlist_auto_interval_hours),
    "http_proxy": CONFIG.http_proxy,
}

# ---------------------------------------------------------------------------
# 内置开源情报源（免 API Key，开箱即用；由管理员在界面启停）
#   adapter_type: http / dnsbl
#   dnsbl.config: {"zone": "...", "resolver": "..."} 可自定义
#
# 方案 C（2026-09-03 在线情报源质量评估收敛）：
#   - 实时层收敛为 3 个 DNSBL 源默认启用（spamhaus_zen/dbl + dronebl）——
#     DNS 协议亚毫秒响应、无限流配额，适合 10 万终端实时检测链路；
#   - SPFBL 邮件评分语义与浏览类过滤错配（仅 .2 计入拦截后价值有限），
#     移出默认启用，保留为可手工启用的内置源；
#   - 威胁域名/C2 情报由离线大名单承载（threatfox hostfile 见
#     app/threat_list.py SOURCES，与 hagezi/oisd 等同链路）；
#   - 九个 HTTP 类源不再预置（适配器注册保留，管理员可手工创建）：
#     单源延迟 1~2s、免费 Key 配额低（10 万终端下未命中流量会打爆配额），
#     历史上仅用于测试中心人工核验，预置价值低。
# ---------------------------------------------------------------------------
# 首次插入即默认启用的源（仅对新库生效；存量库不覆盖管理员选择）
DEFAULT_ENABLED_SOURCES = {"spamhaus_zen", "spamhaus_dbl", "dronebl"}

# 测试环境（DNSF_TESTING=1）不默认启用任何真实源——单元测试不依赖公网，
# 真实 DNSBL 查询网络不稳时返回无结论会走 fail-safe 拦截，串扰断言
if os.environ.get("DNSF_TESTING") == "1":
    DEFAULT_ENABLED_SOURCES = set()

BUILTIN_THREATINTEL = [
    {
        "name": "spamhaus_zen",
        "adapter_type": "dnsbl",
        "base_url": "",
        "config": {"zone": "zen.spamhaus.org", "resolver": "223.5.5.5"},
        "description": "Spamhaus ZEN 综合 IP 信誉黑名单（SBL/XBL/PBL），免 Key",
    },
    {
        "name": "spamhaus_dbl",
        "adapter_type": "dnsbl",
        "base_url": "",
        "config": {"zone": "dbl.spamhaus.org", "resolver": "223.5.5.5"},
        "description": "Spamhaus DBL 域名黑名单（垃圾/钓鱼/恶意软件），免 Key",
    },
    {
        "name": "dronebl",
        "adapter_type": "dnsbl",
        "base_url": "",
        "config": {"zone": "dnsbl.dronebl.org", "resolver": "223.5.5.5"},
        "description": "DroneBL 僵尸网络/滥用 IP 黑名单（垃圾/暴力破解/恶意软件），免 Key",
    },
    {
        "name": "spfbl",
        "adapter_type": "dnsbl",
        "base_url": "",
        "config": {"zone": "dnsbl.spfbl.net", "resolver": "223.5.5.5"},
        "description": "SPFBL 邮件信誉评分清单（仅 127.0.0.2 确认垃圾计入拦截，.3/.4/.5 弱信号忽略；评分信号源，默认停用，可手工启用）",
    },
]

# 已退役的内置源（历史版本由 seed 预置、方案 C 收敛后不再内置）。
# 存量库升级启动时执行清理迁移（见 _retire_builtin_sources）：
#   - 无管理状态的（未启用且未配 Key）→ 直接删除，不再出现在源列表；
#   - 有管理状态的（管理员配过 Key 或启用中）→ 保留，交由管理员自行处置。
_RETIRED_BUILTIN_SOURCES = (
    "urlhaus",           # HTTP API 需 Auth-Key；离线 hostfile 仍在 threat_list 内置
    "threatfox",         # C2 域名情报转 threatfox_hosts 离线大名单承载
    "threatbook",
    "xforce",
    "phishtank",
    "dshield",
    "blocklist_de",
    "otx",
    "greynoise",
)


def _retire_builtin_sources(conn) -> None:
    """清理已退役内置源（方案 C 收敛，2026-09-03）。

    存量库中的退役源分两类处置：
      1. 无管理状态（enabled=0 且 api_key 为空）→ DELETE，
         界面源列表不再出现"僵尸卡片"；
      2. 有管理状态（管理员配过 Key 或启用中）→ 保留，
         打 warning 日志提示管理员自行处置。

    注意：is_builtin=1 的源正常路径禁止删除（路由层 403），
    本函数是唯一的退役出口，仅启动时执行一次。
    仅处置 is_builtin=1 的行——管理员通过 API 手工重建的同名源
    （is_builtin=0）属自定义配置，不在清理范围。

    另：spfbl 语义修正后不再适合默认启用——存量库 enabled=1 时
    自动停用（新库由 DEFAULT_ENABLED_SOURCES 控制为不启用）。
    """
    for name in _RETIRED_BUILTIN_SOURCES:
        cur = conn.execute(
            """SELECT id, enabled, api_key FROM threatintel_api
               WHERE name=? AND is_builtin=1""",
            (name,))
        row = cur.fetchone()
        if row is None:
            continue
        if not row["enabled"] and not row["api_key"]:
            conn.execute("DELETE FROM threatintel_api WHERE id=?",
                         (row["id"],))
            logger.info("退役内置源 %s 无管理状态，已清理删除", name)
        else:
            logger.warning(
                "退役内置源 %s 检测到管理状态（enabled=%s, key=%s），"
                "已保留——方案 C 后不再预置，请管理员自行评估停用/删除",
                name, row["enabled"], "有" if row["api_key"] else "无")

    # spfbl 语义修正：仅 .2 计入拦截后拦截面大幅收窄，存量库若在
    # 启用中则自动停用（新库默认不启用）；保留源本身可手工再启用
    cur = conn.execute(
        "SELECT id FROM threatintel_api WHERE name='spfbl' AND enabled=1")
    row = cur.fetchone()
    if row is not None:
        conn.execute(
            "UPDATE threatintel_api SET enabled=0 WHERE id=?", (row["id"],))
        logger.warning(
            "SPFBL 语义已修正（仅 127.0.0.2 确认垃圾计入拦截，.3/.4/.5 "
            "弱信号忽略），默认启用不再合适——已自动停用，可手工重新启用")
    conn.commit()


def init_builtin_threatintel(conn) -> None:
    """写入内置开源情报源。

    - 不存在则插入（DNSBL 三源默认启用，其余默认停用）；
    - 已存在则仅同步 description（项目维护的说明文字，跟随版本更新），
      不触碰管理员自定义的 config / api_key / enabled 启停状态。
    - _retire_builtin_sources：清理退役源（无状态删除/有状态保留 +
      spfbl 存量自动停用）。
    """
    _retire_builtin_sources(conn)
    for item in BUILTIN_THREATINTEL:
        cur = conn.execute("SELECT id FROM threatintel_api WHERE name=?",
                           (item["name"],))
        row = cur.fetchone()
        if row is None:
            enabled = 1 if item["name"] in DEFAULT_ENABLED_SOURCES else 0
            conn.execute(
                """INSERT INTO threatintel_api
                   (name, adapter_type, base_url, enabled, timeout_ms,
                    is_builtin, config, description)
                   VALUES (?, ?, ?, ?, ?, 1, ?, ?)""",
                (item["name"], item["adapter_type"], item["base_url"],
                 enabled,
                 CONFIG.api_timeout_ms,
                 json.dumps(item["config"], ensure_ascii=False),
                 item["description"]),
            )
        else:
            conn.execute(
                "UPDATE threatintel_api SET description=? WHERE id=?",
                (item["description"], row["id"]),
            )
    conn.commit()


def init_admin(conn) -> None:
    """不存在管理员则创建默认管理员（admin / admin_initial_password）。"""
    cur = conn.execute("SELECT COUNT(*) AS c FROM admin_user")
    if cur.fetchone()["c"] > 0:
        return
    password_hash = bcrypt.hashpw(
        CONFIG.admin_initial_password.encode(), bcrypt.gensalt()
    ).decode()
    conn.execute(
        "INSERT INTO admin_user (username, password_hash) VALUES (?, ?)",
        ("admin", password_hash),
    )
    conn.commit()
    logger.warning(
        "已创建默认管理员 admin，初始密码：%s（生产环境请立即修改！）",
        CONFIG.admin_initial_password,
    )


def init_system_config(conn) -> None:
    """缺失的配置键写入默认值（已存在的键不覆盖）。"""
    for key, value in DEFAULT_SYSTEM_CONFIG.items():
        conn.execute(
            "INSERT OR IGNORE INTO system_config (key, value) VALUES (?, ?)",
            (key, value),
        )
    conn.commit()


def init_all() -> None:
    conn = get_conn()
    init_admin(conn)
    init_system_config(conn)
    init_builtin_threatintel(conn)
    logger.info("平台初始化完成（数据库：%s）", CONFIG.database)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_all()
