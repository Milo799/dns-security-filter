"""威胁情报源 api_key 落库加密（Fernet 对称加密）。

背景：PRD 与 AI_AGENTS 承诺"api_key 加密存储"，此前实现仅 Web 回显
脱敏（●●●●●●+尾4位），SQLite 中为明文——生产就绪度评估（2026-08-31）
列为 P1 缺口。本模块补齐：

- 算法：Fernet（AES-128-CBC + HMAC-SHA256，含时间戳与随机 IV）
- 密钥派生：platform.yaml 的 web.jwt_secret → SHA-256 → urlsafe base64
  （不新增独立密钥文件：jwt_secret 已是"生产必改项"，安装脚本自动
   生成 32 字节随机值；改 jwt_secret 会使旧密文解不开——按明文回退
   处理，管理员重新保存一次 Key 即可，属可接受的运维边界）
- 兼容策略（decrypt_key）：
    - 空串 → 空串
    - 带 "enc:" 前缀 → 解密；解密失败返回 ""（记日志，不抛异常——
      检测链路绝不能因密钥问题挂掉）
    - 无前缀 → 视为历史明文，原样返回（存量库平滑兼容，不强制迁移）
- 存量迁移（migrate_plaintext_keys）：启动时把无前缀的非空 api_key
  批量加密为 "enc:..."，幂等可重跑；Web（main.py startup）负责调用，
  DNS 进程只读不写，不参与迁移
- 加密写入点：threatintel 路由 create/update；读取解密点：
  adapters.get_enabled_adapters / threatintel 路由连通性测试
"""

import base64
import hashlib
import logging

from cryptography.fernet import Fernet, InvalidToken

from config import CONFIG

logger = logging.getLogger("platform.crypto")

_PREFIX = "enc:"                 # 密文标记前缀（区分历史明文）
_fernet: Fernet | None = None    # 惰性初始化（CONFIG.jwt_secret 加载后）


def _get_fernet() -> Fernet:
    """从 jwt_secret 确定性派生 Fernet 密钥（进程内单例）。"""
    global _fernet
    if _fernet is None:
        digest = hashlib.sha256(
            CONFIG.web.jwt_secret.encode("utf-8")).digest()
        _fernet = Fernet(base64.urlsafe_b64encode(digest))
    return _fernet


def encrypt_key(plaintext: str) -> str:
    """加密 api_key → 'enc:<fernet token>'。空串原样返回。"""
    if not plaintext:
        return ""
    if plaintext.startswith(_PREFIX):
        return plaintext          # 已是密文，避免二次加密
    token = _get_fernet().encrypt(plaintext.encode("utf-8"))
    return _PREFIX + token.decode("ascii")


def decrypt_key(stored: str) -> str:
    """解密落库值 → 明文。

    - 空串 / 历史明文（无前缀）→ 原样返回
    - 'enc:' 前缀但解密失败（jwt_secret 已更换）→ 返回 ""并记警告；
      适配器拿到空 Key 走"未配 Key 不发请求"既有语义，三态无结论，
      不影响检测链路可用性
    """
    if not stored or not stored.startswith(_PREFIX):
        return stored
    try:
        return _get_fernet().decrypt(
            stored[len(_PREFIX):].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError) as e:
        logger.warning("api_key 解密失败（jwt_secret 可能已更换）：%s", e)
        return ""


def migrate_plaintext_keys() -> int:
    """存量明文 api_key 批量加密（幂等）。返回本次迁移条数。

    由 Web 进程启动时调用（main.py startup）；只处理非空且无 enc:
    前缀的行。SQLite 单写者，UPDATE 走本线程连接即可。
    """
    from app.db import db_cursor
    migrated = 0
    with db_cursor() as cur:
        cur.execute(
            "SELECT id, api_key FROM threatintel_api "
            "WHERE api_key != '' AND api_key IS NOT NULL")
        rows = cur.fetchall()
    for row in rows:
        key = row["api_key"]
        if key.startswith(_PREFIX):
            continue
        encrypted = encrypt_key(key)
        with db_cursor() as cur:
            cur.execute(
                "UPDATE threatintel_api SET api_key=? WHERE id=?",
                (encrypted, row["id"]))
        migrated += 1
    if migrated:
        logger.info("已加密 %d 条存量明文 api_key", migrated)
    return migrated
