"""离线大名单自动更新调度（方案 A：服务内定时任务）。

- 由 main.py 在应用启动时挂载 asyncio 后台任务（lifespan）；
- 每个周期 sleep 后检查 CONFIG.threatlist_auto_update 开关；
  每周期重新读取间隔，支持 Web 热修改无需重启；
- 开启时对"已导入且启用"的内置来源执行一轮整源替换导入
  （threat_list.auto_update_once），单来源失败已隔离；
- 全程 try/except 兜底：任何异常只记日志，绝不中断 DNS/Web 服务。

注：同步的下载+导入在 to_thread 线程池中执行，避免阻塞事件循环
（列表最大 20MB，一次更新可能耗时数十秒）。
"""

import asyncio
import logging

from config import CONFIG
from app import threat_list

logger = logging.getLogger("platform.app.auto_update")

_INTERVAL_MIN_H = 1          # 1 小时
_INTERVAL_MAX_H = 24 * 30    # 30 天


def interval_seconds() -> int:
    """读取配置间隔（小时）→ 秒；非法值回退 24 小时。"""
    try:
        h = int(getattr(CONFIG, "threatlist_auto_interval_hours", 24))
    except (TypeError, ValueError):
        h = 24
    h = max(_INTERVAL_MIN_H, min(h, _INTERVAL_MAX_H))
    return h * 3600


async def auto_update_loop() -> None:
    """后台循环：sleep 间隔 → 开关开启则执行一轮自动更新。"""
    while True:
        await asyncio.sleep(interval_seconds())
        if not getattr(CONFIG, "threatlist_auto_update", False):
            continue
        try:
            results = await asyncio.to_thread(threat_list.auto_update_once)
            ok = [k for k, v in results.items() if v["ok"]]
            fail = [k for k, v in results.items() if not v["ok"]]
            if fail:
                logger.warning("大名单自动更新：成功 %s，失败 %s", ok, fail)
            elif ok:
                logger.info("大名单自动更新完成：%s", ok)
        except Exception as e:   # 兜底，绝不中断服务
            logger.warning("大名单自动更新异常：%s", e)
