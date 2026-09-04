"""登录防爆破双闸（迭代 31，Task #172）。

账号闸：同一用户名连续登录失败 N 次（login_lockout_threshold）→ 锁定
M 分钟（login_lockout_minutes）；锁定期间即使密码正确也不放行。
IP 闸：同一来源 IP 在滑动窗口（login_ip_window_minutes）内累计失败
N 次（login_ip_threshold）→ 封禁 M 分钟（login_ip_block_minutes）；
防"换账号字典攻击"（账号闸管不住的旁路）。

实现约束：
- 纯内存计数（dict + threading.Lock）：重启清零（可接受——锁定是短时
  防护，重启窗口的爆破收益极低）；不落库、不写 cross_sync（Web 进程
  独享，DNS 检测链路零接触）；
- 4 参数全部走 CONFIG（system_config 热生效，runtime._INT_KEYS 同步）；
- 阈值=0 表示对应闸禁用（逃生开关：管理员被误锁时改配置即可，或等
  锁定自然过期/重启进程）。

审计策略：失败不逐条写（防刷爆审计表）；只在"触发锁定/封禁"这种
状态变化时刻写一条（login_lockout / login_ip_block）。
"""

import threading
import time

import logging

from config import CONFIG

logger = logging.getLogger("platform.login_guard")

_LOCK = threading.Lock()

# {username: {"fails": int, "locked_until": float}}
_account_state: dict = {}
# {ip: {"events": [timestamps], "blocked_until": float}}
_ip_state: dict = {}


def _now() -> float:
    return time.monotonic()


def _audit(operator: str, action: str, detail: dict) -> None:
    """锁定/封禁事件写审计（延迟导入防循环依赖）。"""
    try:
        from app.audit import write_audit
        write_audit(operator, action, detail)
    except Exception:  # 审计失败不阻断登录主流程
        logger.warning("防爆破审计写入失败（%s）", action, exc_info=True)


def account_status(username: str) -> tuple[bool, int]:
    """返回 (是否锁定, 剩余秒数)。锁定过期时惰性清理并顺带重置计数。"""
    with _LOCK:
        st = _account_state.get(username)
        if not st:
            return False, 0
        now = _now()
        if st.get("locked_until", 0) > now:
            return True, int(st["locked_until"] - now)
        # 锁定已过：本次检查即解锁，计数归零（全新窗口）
        if "locked_until" in st:
            _account_state.pop(username, None)
        return False, 0


def ip_status(ip: str) -> tuple[bool, int]:
    """返回 (是否封禁, 剩余秒数)。封禁过期时惰性清理。"""
    if not ip:
        return False, 0
    with _LOCK:
        st = _ip_state.get(ip)
        if not st:
            return False, 0
        now = _now()
        if st.get("blocked_until", 0) > now:
            return True, int(st["blocked_until"] - now)
        if "blocked_until" in st:
            _ip_state.pop(ip, None)
        return False, 0


def record_failure(username: str, ip: str) -> dict:
    """登录失败后调用：累计双闸计数，达到阈值即锁定/封禁并写审计。

    返回状态摘要供登录端点拼装提示（是否刚触发锁定、剩余秒数）。
    """
    now = _now()
    triggered = {}
    with _LOCK:
        # ---- 账号闸 ----
        thr = CONFIG.login_lockout_threshold
        if thr > 0:
            st = _account_state.setdefault(username, {"fails": 0})
            st["fails"] += 1
            if st["fails"] >= thr and "locked_until" not in st:
                lock_s = CONFIG.login_lockout_minutes * 60
                st["locked_until"] = now + lock_s
                triggered["account_locked"] = True
                triggered["account_lock_seconds"] = lock_s
        # ---- IP 闸 ----
        ip_thr = CONFIG.login_ip_threshold
        if ip and ip_thr > 0:
            win_s = CONFIG.login_ip_window_minutes * 60
            ist = _ip_state.setdefault(ip, {"events": []})
            events = [t for t in ist["events"] if now - t < win_s]
            events.append(now)
            ist["events"] = events
            if len(events) >= ip_thr and "blocked_until" not in ist:
                block_s = CONFIG.login_ip_block_minutes * 60
                ist["blocked_until"] = now + block_s
                triggered["ip_blocked"] = True
                triggered["ip_block_seconds"] = block_s
    # 审计放锁外（写库慢不该持有内存锁）
    if triggered.get("account_locked"):
        _audit("system", "login_lockout", {
            "username": username,
            "minutes": CONFIG.login_lockout_minutes,
            "failures": CONFIG.login_lockout_threshold,
        })
        logger.warning("账号 %s 连续失败 %d 次，锁定 %d 分钟",
                       username, CONFIG.login_lockout_threshold,
                       CONFIG.login_lockout_minutes)
    if triggered.get("ip_blocked"):
        _audit("system", "login_ip_block", {
            "ip": ip,
            "window_minutes": CONFIG.login_ip_window_minutes,
            "failures": CONFIG.login_ip_threshold,
            "block_minutes": CONFIG.login_ip_block_minutes,
        })
        logger.warning("IP %s 窗口内失败 %d 次，封禁 %d 分钟",
                       ip, CONFIG.login_ip_threshold,
                       CONFIG.login_ip_block_minutes)
    return triggered


def record_success(username: str, ip: str) -> None:
    """登录成功后调用：清账号闸计数；IP 闸计数保留（累计失败防绕过——
    成功登录不清 IP 失败历史，字典攻击者换回正确账号也已被计入窗口）。"""
    with _LOCK:
        _account_state.pop(username, None)


def reset() -> None:
    """清空全部计数（测试用）。"""
    with _LOCK:
        _account_state.clear()
        _ip_state.clear()


def guard_stats() -> dict:
    """观测：当前锁定账号/封禁 IP 快照（GET /api/auth/guard-stats）。"""
    now = _now()
    with _LOCK:
        locked_accounts = [
            {"username": u, "remaining_s": int(st["locked_until"] - now)}
            for u, st in _account_state.items()
            if st.get("locked_until", 0) > now
        ]
        blocked_ips = [
            {"ip": i, "remaining_s": int(st["blocked_until"] - now)}
            for i, st in _ip_state.items()
            if st.get("blocked_until", 0) > now
        ]
    return {"locked_accounts": locked_accounts, "blocked_ips": blocked_ips}
