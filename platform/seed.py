"""初始化：默认管理员 + 默认系统配置 + 内置开源情报源（首次启动时执行）。"""

import json
import logging

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
    "detection_enabled": str(int(CONFIG.detection_enabled)),
    "threatlist_auto_update": str(int(CONFIG.threatlist_auto_update)),
    "threatlist_auto_interval_hours": str(CONFIG.threatlist_auto_interval_hours),
}

# ---------------------------------------------------------------------------
# 内置开源情报源（免 API Key，开箱即用；默认停用，由管理员在界面启用）
#   adapter_type: http / dnsbl
#   dnsbl.config: {"zone": "...", "resolver": "..."} 可自定义
# ---------------------------------------------------------------------------
BUILTIN_THREATINTEL = [
    {
        "name": "spamhaus_zen",
        "adapter_type": "dnsbl",
        "base_url": "",
        "config": {"zone": "zen.spamhaus.org"},
        "description": "Spamhaus ZEN 综合 IP 信誉黑名单（SBL/XBL/PBL），免 Key",
    },
    {
        "name": "spamhaus_dbl",
        "adapter_type": "dnsbl",
        "base_url": "",
        "config": {"zone": "dbl.spamhaus.org"},
        "description": "Spamhaus DBL 域名黑名单（垃圾/钓鱼/恶意软件），免 Key",
    },
    {
        "name": "dronebl",
        "adapter_type": "dnsbl",
        "base_url": "",
        "config": {"zone": "dnsbl.dronebl.org"},
        "description": "DroneBL 僵尸网络/滥用 IP 黑名单（垃圾/暴力破解/恶意软件），免 Key",
    },
    {
        "name": "spfbl",
        "adapter_type": "dnsbl",
        "base_url": "",
        "config": {"zone": "dnsbl.spfbl.net"},
        "description": "SPFBL 综合垃圾/恶意域名与 IP 黑名单，免 Key",
    },
    {
        "name": "urlhaus",
        "adapter_type": "http",
        "base_url": "https://urlhaus-api.abuse.ch",
        "config": {"note": "需 Auth-Key（https://auth.abuse.ch/ 免费申请）填入 API Key；官方限速约 5 秒/次，建议默认停用，手动测试用"},
        "description": "URLhaus（abuse.ch）恶意 URL 分发库，支持域名与 IP，需 Auth-Key",
    },
    {
        "name": "threatfox",
        "adapter_type": "http",
        "base_url": "https://threatfox-api.abuse.ch",
        "config": {"note": "需免费注册 Auth-Key（auth.abuse.ch），编辑本源的 api_key 或 config 填写"},
        "description": "ThreatFox（abuse.ch）僵尸网络 C2 指标库，支持域名与 IP",
    },
    {
        "name": "threatbook",
        "adapter_type": "http",
        "base_url": "https://api.threatbook.cn",
        "config": {"note": "需免费注册 apikey（x.threatbook.cn）；个人版约 50 次/天，建议人工核查用"},
        "description": "微步在线 ThreatBook 威胁情报（C2/恶意软件/钓鱼），支持域名与 IP",
    },
    {
        "name": "xforce",
        "adapter_type": "http",
        "base_url": "https://api.xforce.ibmcloud.com",
        "config": {"note": "免费非商业 API；需 exchange.xforce.ibmcloud.com 生成 Key+Password，config 填 api_password，评分阈值 score_threshold 默认 5"},
        "description": "IBM X-Force Exchange 威胁情报（评分制 0-10），支持域名与 IP",
    },
    {
        "name": "phishtank",
        "adapter_type": "http",
        "base_url": "https://checkurl.phishtank.com",
        "config": {"note": "app_key 可选；无 Key 限速严格，适合人工核查/低频场景"},
        "description": "PhishTank（OpenDNS）钓鱼 URL 库，免 Key",
    },
    {
        "name": "dshield",
        "adapter_type": "http",
        "base_url": "https://isc.sans.edu",
        "config": {"min_count": 500, "max_age_days": 14},
        "description": "SANS DShield 全球蜜罐攻击源 IP 信誉，免 Key",
    },
    {
        "name": "blocklist_de",
        "adapter_type": "http",
        "base_url": "https://api.blocklist.de",
        "config": {"min_attacks": 1},
        "description": "Blocklist.de 攻击源 IP（SSH/邮件/Web 暴力破解与扫描），免 Key",
    },
    {
        "name": "otx",
        "adapter_type": "http",
        "base_url": "https://otx.alienvault.com",
        "config": {"note": "需免费注册 Key（otx.alienvault.com 个人版额度宽松），编辑本源的 api_key 或 config 填写"},
        "description": "AlienVault OTX 开放威胁情报社区（恶意域名/IP 量大、覆盖广），支持域名与 IP",
    },
    {
        "name": "greynoise",
        "adapter_type": "http",
        "base_url": "https://api.greynoise.io",
        "config": {"note": "需免费社区 Key（docs.greynoise.io/reference/community-ip-lookup），仅 IP；只拦 malicious，扫描器误拦专治"},
        "description": "GreyNoise 互联网扫描器识别（区分恶意扫描与良性噪声），仅 IP",
    },
]


def init_builtin_threatintel(conn) -> None:
    """写入内置开源情报源。

    - 不存在则插入（默认停用）；
    - 已存在则仅同步 description（项目维护的说明文字，跟随版本更新），
      不触碰管理员自定义的 config / api_key / enabled 启停状态。
    """
    for item in BUILTIN_THREATINTEL:
        cur = conn.execute("SELECT id FROM threatintel_api WHERE name=?",
                           (item["name"],))
        row = cur.fetchone()
        if row is None:
            conn.execute(
                """INSERT INTO threatintel_api
                   (name, adapter_type, base_url, enabled, timeout_ms,
                    is_builtin, config, description)
                   VALUES (?, ?, ?, 0, ?, 1, ?, ?)""",
                (item["name"], item["adapter_type"], item["base_url"],
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
