"""跨进程状态轮询：DNS 进程感知 Web 进程的配置与名单变更。

背景（2026-08-31 解析速度评估发现的部署问题）：生产为双进程部署
（platform-dns + platform-web 或 Docker 单容器双进程），Web 界面的
配置修改与名单导入只更新 Web 进程内存 + SQLite；DNS 进程不感知——
system_config 热配置失效（runtime 仅启动时 sync）、
filter_list / threat_list 内存缓存不失效（用旧名单）、
情报源变更不清结论缓存。

方案：DNS 进程起 daemon 线程按周期轮询各表 MAX(updated_at)，
变化即触发对应动作（sync_config / invalidate）。SQLite 读多线程
安全（WAL + 线程本地连接），轮询在自己的线程与连接上进行，
完全不触碰 DNS 应答热路径。

粒度说明：datetime('now','localtime') 秒级粒度——同秒内连续两次
变更可能漏检后一次，但下一次任何变更都会再次触发；轮询周期内
（默认 60s）的业务操作语义上可接受（等价"最长 60s 生效"）。
"""

import logging
import threading
import time

from app.db import db_cursor

logger = logging.getLogger("platform.cross_sync")

POLL_INTERVAL_S = 60          # 轮询周期（秒）

# 各表上次观测的版本（MAX(updated_at) 字符串）；None = 未建立基线
_last: dict[str, str | None] = {
    "system_config": None,
    "filter_list": None,
    "threatintel_api": None,
    "threat_list": None,
}


def _table_version(table: str) -> str | None:
    """取表版本（MAX(updated_at)）。表空返回 ''，异常返回 None（跳过本轮）。"""
    try:
        with db_cursor() as cur:
            cur.execute(f"SELECT MAX(updated_at) FROM {table}")   # noqa: S608 白名单表名
            row = cur.fetchone()
            return str(row[0]) if row and row[0] is not None else ""
    except Exception as e:
        logger.warning("跨进程轮询读 %s 失败：%s", table, e)
        return None


def poll_once() -> dict[str, bool]:
    """执行一轮变更检查，返回 {表名: 是否有变更}（仅含有变更的表）。

    首次调用只建立基线不触发动作（DNS 进程启动时缓存本来就是空的）。
    单元测试可直接调用本函数验证联动。
    """
    changed: dict[str, bool] = {}

    v = _table_version("system_config")
    if v is not None and _last["system_config"] is not None and v != _last["system_config"]:
        from app.runtime import sync_config_from_db
        sync_config_from_db()
        changed["system_config"] = True
    _last["system_config"] = v

    v = _table_version("filter_list")
    if v is not None and _last["filter_list"] is not None and v != _last["filter_list"]:
        from app.db import invalidate_list_cache
        invalidate_list_cache()
        changed["filter_list"] = True
    _last["filter_list"] = v

    v = _table_version("threatintel_api")
    if v is not None and _last["threatintel_api"] is not None and v != _last["threatintel_api"]:
        import domain_cache
        import ip_cache
        domain_cache.threatintel_invalidate()
        ip_cache.threatintel_invalidate()
        changed["threatintel_api"] = True
    _last["threatintel_api"] = v

    v = _table_version("threat_list")
    if v is not None and _last["threat_list"] is not None and v != _last["threat_list"]:
        from app import threat_list
        threat_list.invalidate()
        changed["threat_list"] = True
    _last["threat_list"] = v

    return changed


def reset_baseline() -> None:
    """清空基线（测试用：强制下一轮视为首次）。"""
    for k in _last:
        _last[k] = None


def start(interval_s: int = POLL_INTERVAL_S) -> None:
    """启动后台轮询线程（daemon，不阻塞服务启动）。"""
    def _loop() -> None:
        poll_once()                      # 建立基线
        while True:
            time.sleep(interval_s)
            try:
                changed = poll_once()
                if changed:
                    logger.info("检测到 Web 进程变更并已同步：%s",
                                ", ".join(changed))
            except Exception:
                logger.exception("跨进程轮询异常（下轮重试）")

    threading.Thread(target=_loop, name="cross-sync", daemon=True).start()
    logger.info("跨进程状态轮询已启动（周期 %ds）", interval_s)
