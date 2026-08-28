"""威胁情报链路熔断与降级 —— 10 万终端前置开发项第 2 项。

背景（生产部署方案第零节）：fail-safe 语义在 10 万终端规模下有放大风险——
在线情报源被限流/故障时，全部查询"无结论 → 默认拦截"，等价全网断网。
本模块提供两层防护：

1) 源级熔断（circuit breaker，逐适配器）：
   - 单个情报源连续失败 N 次（failure_threshold）→ 熔断（open），
     检测主流程跳过该源，不再浪费线程与超时等待；
   - 冷却 open_timeout_s 后进入半开（half-open），放行 1 次探测查询；
   - 探测成功 → 关闭（closed，计数清零）；失败 → 重新熔断，冷却计时重来。
   - "失败"= 适配器返回 None（超时/网络/鉴权异常）；异常同样计失败。

2) 路径级降级（degradation，在线情报整体）：
   - query_threatintel_domain 走到 fail-safe 分支（全部源无结论）时计数；
   - 连续 M 次（degrade_threshold）→ 触发降级窗口（degrade_window_s）：
     窗口内在线情报检测整体跳过，按"未命中"处理继续放行后续环节
     （本地黑名单 / 离线大名单 / IP 后置仍在，安全底线不破）；
   - 窗口结束自动恢复，恢复后阈值计数重新累计；
   - failsafe_mode 配置决定降级行为：
       intercept（默认，现网语义）: fail-safe 默认拦截（不降级）
       degrade（生产推荐）       : 触发阈值后降级放行
   - 注意：IP 后置过滤（query_threatintel_ip / ip_postfilter）不降级——
     单域名 IP 数量少（1~8 个），且部分剔除/拦截不影响域名整体可用性，
     保持 fail-safe 原语义。

线程模型：检测主流程在线程池（run_in_executor）并发调用，本模块
仅做计数与状态读写，统一锁保护；无 IO，锁内耗时纳秒级。
"""

import logging
import threading
import time

from config import CONFIG

logger = logging.getLogger("platform.circuit_breaker")

_LOCK = threading.Lock()

# ---- 源级熔断状态（按适配器 name）----
# {name: {"state": "closed"|"open"|"half-open",
#         "failures": int,          # closed 态连续失败计数
#         "opened_at": float}}      # 熔断时刻（monotonic）
_BREAKERS: dict[str, dict] = {}

# ---- 路径级降级状态（进程内单例）----
_DEGRADE = {
    "consecutive_failsafes": 0,   # 连续 fail-safe 计数
    "degraded_until": 0.0,        # 降级窗口截止时刻（monotonic），0=未降级
    "degrade_count": 0,           # 累计触发降级次数（观测用）
}

# 事件钩子（测试注入用）：函数列表，降级触发/恢复时回调
_ON_DEGRADE_CHANGE: list = []


def _cfg_int(attr: str, default: int) -> int:
    try:
        return max(0, int(getattr(CONFIG, attr)))
    except (TypeError, ValueError, AttributeError):
        return default


# ---------------------------------------------------------------------------
# 源级熔断
# ---------------------------------------------------------------------------

def allows_source(name: str) -> bool:
    """该情报源当前是否允许调用（检测主流程逐源判断）。

    closed → 允许；open 且已过冷却 → 转 half-open 放行本次（探测）；
    open 未到冷却 → 拒绝；half-open → 拒绝（探测已在途，避免并发放行多个探测）。
    """
    now = time.monotonic()
    with _LOCK:
        br = _BREAKERS.get(name)
        if br is None:
            return True
        if br["state"] == "closed":
            return True
        if br["state"] == "open":
            if now - br["opened_at"] >= _cfg_int("cb_open_timeout_s", 60):
                br["state"] = "half-open"
                return True                  # 放行一次探测
            return False
        return False                         # half-open：探测在途


def record_success(name: str) -> None:
    """适配器返回有结论（含明确未命中）→ 熔断器关闭，计数清零。"""
    with _LOCK:
        br = _BREAKERS.get(name)
        if br is not None:
            br["state"] = "closed"
            br["failures"] = 0


def record_failure(name: str) -> None:
    """适配器返回 None（无结论）或抛异常 → 计失败，达阈值熔断。"""
    threshold = _cfg_int("cb_failure_threshold", 5)
    now = time.monotonic()
    with _LOCK:
        br = _BREAKERS.setdefault(
            name, {"state": "closed", "failures": 0, "opened_at": 0.0})
        if br["state"] == "half-open":
            # 探测失败：直接重新熔断
            br["state"] = "open"
            br["opened_at"] = now
            br["failures"] = threshold
            return
        if br["state"] == "open":
            return                           # open 态不应被调用（防御）
        br["failures"] += 1
        if threshold > 0 and br["failures"] >= threshold:
            br["state"] = "open"
            br["opened_at"] = now
            logger.warning("情报源 %s 连续失败 %d 次，熔断 %ds",
                           name, br["failures"],
                           _cfg_int("cb_open_timeout_s", 60))


def source_states() -> dict[str, dict]:
    """全部熔断器状态快照（诊断/状态接口用）。"""
    now = time.monotonic()
    with _LOCK:
        out = {}
        for name, br in _BREAKERS.items():
            state = br["state"]
            if state == "open" and now - br["opened_at"] >= \
                    _cfg_int("cb_open_timeout_s", 60):
                state = "half-open"          # 展示口径与 allows_source 一致
            out[name] = {"state": state, "failures": br["failures"]}
        return out


# ---------------------------------------------------------------------------
# 路径级降级（在线情报域名检测整体）
# ---------------------------------------------------------------------------

def failsafe_mode() -> str:
    """当前 fail-safe 模式：intercept（默认拦截）/ degrade（阈值降级放行）。"""
    try:
        mode = str(getattr(CONFIG, "failsafe_mode", "intercept"))
    except AttributeError:
        return "intercept"
    return mode if mode in ("intercept", "degrade") else "intercept"


def is_degraded() -> bool:
    """当前是否处于降级窗口（在线情报域名检测整体跳过）。"""
    with _LOCK:
        return time.monotonic() < _DEGRADE["degraded_until"]


def degrade_remaining_s() -> float:
    with _LOCK:
        return max(0.0, _DEGRADE["degraded_until"] - time.monotonic())


def record_failsafe() -> None:
    """query_threatintel_domain 全源无结论（fail-safe）时调用。

    - intercept 模式：仅计数（供状态观测），不触发降级；
    - degrade 模式：连续达阈值 → 开降级窗口，窗口内跳过在线检测。
    """
    threshold = _cfg_int("degrade_threshold", 3)
    window = _cfg_int("degrade_window_s", 300)
    with _LOCK:
        _DEGRADE["consecutive_failsafes"] += 1
        if failsafe_mode() != "degrade" or threshold <= 0:
            return
        if _DEGRADE["consecutive_failsafes"] >= threshold \
                and time.monotonic() >= _DEGRADE["degraded_until"]:
            _DEGRADE["degraded_until"] = time.monotonic() + window
            _DEGRADE["degrade_count"] += 1
            _DEGRADE["consecutive_failsafes"] = 0
            logger.warning(
                "在线情报连续 fail-safe 达阈值（%d），降级 %ds："
                "窗口内域名在线检测跳过，本地名单与大名单仍生效",
                threshold, window)
            hooks = list(_ON_DEGRADE_CHANGE)
        else:
            hooks = []
    for cb in hooks:      # 锁外回调，避免死锁
        try:
            cb(True)
        except Exception:
            pass


def record_verdict() -> None:
    """query_threatintel_domain 有结论（含明确未命中）时调用：恢复计数。"""
    with _LOCK:
        was_degrading_window = time.monotonic() < _DEGRADE["degraded_until"]
        _DEGRADE["consecutive_failsafes"] = 0
        if was_degrading_window:
            # 窗口内出现了有结论的查询（半开探测性质）→ 提前结束降级
            _DEGRADE["degraded_until"] = 0.0
            _DEGRADE["degrade_count"] = _DEGRADE.get("degrade_count", 0)
            logger.info("在线情报恢复有结论，提前结束降级窗口")
            hooks = list(_ON_DEGRADE_CHANGE)
        else:
            hooks = []
    for cb in hooks:
        try:
            cb(False)
        except Exception:
            pass


def degrade_state() -> dict:
    """降级状态快照（状态接口用）。

    注意：内部不能再调用 is_degraded()/degrade_remaining_s()——二者各自
    抢 _LOCK，与本函数形成不可重入死锁（threading.Lock 非 RLock）。
    """
    now = time.monotonic()
    with _LOCK:
        remaining = max(0.0, _DEGRADE["degraded_until"] - now)
        return {
            "mode": failsafe_mode(),
            "degraded": remaining > 0,
            "degrade_remaining_s": round(remaining, 1),
            "consecutive_failsafes": _DEGRADE["consecutive_failsafes"],
            "degrade_count": _DEGRADE["degrade_count"],
        }


def reset_all() -> None:
    """全量复位（测试用）。"""
    with _LOCK:
        _BREAKERS.clear()
        _DEGRADE.update(consecutive_failsafes=0, degraded_until=0.0,
                        degrade_count=0)
