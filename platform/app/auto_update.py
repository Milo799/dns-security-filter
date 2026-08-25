"""离线大名单自动更新调度（方案 A：服务内定时任务）。

- 由 main.py 在应用启动时挂载 asyncio 后台任务（lifespan）；
- 每个 tick sleep 后检查 CONFIG.threatlist_auto_update 开关；
  每 tick 重新读取间隔，支持 Web 热修改无需重启；
- tick 间隔 = min(用户配置间隔, 各内置来源最小更新周期)：
  这样 URLhaus（30 分钟）这类高及时小名单能被及时调度，
  而各来源是否真正更新由其 update_interval_s + 最近导入时间决定
  （threat_list.auto_update_once 内部判断，未到期源标记 skipped）；
- 开启时对"已导入且启用"的内置来源执行一轮检查（threat_list.auto_update_once），
  单来源失败已隔离；
- 全程 try/except 兜底：任何异常只记日志，绝不中断 DNS/Web 服务。

注：同步的下载+导入在 to_thread 线程池中执行，避免阻塞事件循环
（列表最大 20MB，一次更新可能耗时数十秒）。
"""

import asyncio
import logging

from config import CONFIG
from app import threat_list

logger = logging.getLogger("platform.app.auto_update")

_INTERVAL_MIN_H = 1          # 1 小时（用户配置下限）
_INTERVAL_MAX_H = 24 * 30    # 30 天
_TICK_MIN_S = 60             # tick 下限，防止配置异常导致忙循环


def interval_seconds() -> int:
    """读取配置间隔（小时）→ 秒；非法值回退 24 小时。"""
    try:
        h = int(getattr(CONFIG, "threatlist_auto_interval_hours", 24))
    except (TypeError, ValueError):
        h = 24
    h = max(_INTERVAL_MIN_H, min(h, _INTERVAL_MAX_H))
    return h * 3600


def tick_seconds() -> int:
    """后台循环检查间隔：取配置间隔与各内置来源最小更新周期的小值。

    使短周期源（urlhaus 30 分钟）能被及时调度；普通来源仍由
    auto_update_once 内各自的 update_interval_s 到期判断决定是否更新。
    """
    min_src = min((s.get("update_interval_s", 24 * 3600)
                   for s in threat_list.SOURCES), default=24 * 3600)
    return max(_TICK_MIN_S, min(interval_seconds(), min_src))


async def auto_update_loop() -> None:
    """后台循环：sleep tick → 开关开启则执行一轮自动更新检查。"""
    while True:
        await asyncio.sleep(tick_seconds())
        if not getattr(CONFIG, "threatlist_auto_update", False):
            continue
        try:
            results = await asyncio.to_thread(threat_list.auto_update_once)
            ok = [k for k, v in results.items() if v["ok"] and not v.get("skipped")]
            fail = [k for k, v in results.items() if not v["ok"]]
            if fail:
                logger.warning("大名单自动更新：成功 %s，失败 %s", ok, fail)
            elif ok:
                logger.info("大名单自动更新完成：%s", ok)
        except Exception as e:   # 兜底，绝不中断服务
            logger.warning("大名单自动更新异常：%s", e)
