"""NRD 新注册域名检测层（迭代 40）——RDAP 注册时间查询。

定位（与 threatintel 适配器的关系）：
  - **独立检测层**，不进 ADAPTER_REGISTRY、不参与 fusion_strategy 融合、
    不计入 circuit_breaker 熔断/降级——域名年龄是确定性事实（注册局
    官方数据），不是"多源投票"型情报，单独判定单独落日志；
  - 插在检测链 threat_list（离线大名单）之后、threatintel（在线融合）
    之前（detectors.process_query 4.7 段）。

检测语义（whoisit 三态 → 平台动作）：
  - 成功 → registration_date 与 now 差值 ≤ nrd_max_age_days 判"新注册"；
  - UnsupportedError（TLD 无 RDAP 服务，如 .cn/.local）→ 跳过不误判
    ——这是路由表事实（本地判断，不发网络请求），**绝不**触发 fail-safe；
  - ResourceDoesNotExist（域名未注册）→ 跳过（能解析说明已注册，
    多为数据延迟，宁漏勿误）；
  - QueryError/RateLimitedError（真失败）→ 跳过放行，不计熔断失败
    （NRD 是辅助信号，网络故障期间不应影响主链路可用性）。

性能设计（10 万终端）：
  - TLD 前置过滤：nrd_tlds 名单外的域名（.com/.net/.cn 等主流 TLD）
    本地判断直接跳过，零网络开销；
  - 注册时间永久缓存：域名年龄只增不减，查得一次永不重查——
    nrd_cache 表（SQLite 持久化）+ 进程内存 dict（热路径读内存）；
  - 查询超时 5s（whoisit 默认 10s 太长）；follow_related=False 必带
    （否则追加注册商子查询，实测 9.8s vs 1.3~1.6s）；
  - whoisit bootstrap（IANA RDAP 路由表）启动后台预热：优先加载
    本地缓存文件（data/rdap_bootstrap.json，24h 内有效），过期或
    不存在则从 data.iana.org 拉取并落盘，之后每 24h 后台刷新一次。

观测（queue_stats 同款口径）：
  - 内存计数器（锁内纳秒级读写）：查询/命中新注册/缓存命中/TLD 跳过/
    不支持跳过/失败跳过各计数，GET /api/nrd/stats 快照；
  - observe 模式：命中也只记日志（reason=nrd_observe，action=observe）
    不拦截，用于上线前评估误报率；intercept 模式真正拦截（reason=nrd）。

线程安全：检测主流程多线程（run_in_executor worker）并发调用
is_new_registration；内存缓存读写与统计计数均持锁。
"""

import logging
import math
import os
import threading
import time
from datetime import datetime, timezone

from config import CONFIG

logger = logging.getLogger("platform.rdap_nrd")

try:
    import whoisit
    import whoisit.errors as wi_errors
    import whoisit.utils as wi_utils
    _HAS_WHOISIT = True
except ImportError:                     # 部署缺依赖：整层跳过（不致命）
    whoisit = None
    wi_errors = None
    wi_utils = None
    _HAS_WHOISIT = False

# ---------------------------------------------------------------------------
# 状态
# ---------------------------------------------------------------------------

_LOCK = threading.Lock()

# 域名 → 注册时间（datetime, UTC）进程内存缓存（热路径只读此 dict）
_MEM_CACHE: dict[str, datetime] = {}

# 内存缓存是否已从 SQLite 加载（进程启动后首次调用时懒加载）
_LOADED = False

# whoisit bootstrap 是否就绪（后台预热线程置位；未就绪时查询会触发
# 同步 bootstrap——首次约 1~2s 拉取 IANA 路由表，预热就是为了避免
# 首条真实查询承担这个延迟）
_BOOTSTRAP_READY = False

# bootstrap 本地缓存文件（与 platform.db 同目录）
_BOOTSTRAP_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "rdap_bootstrap.json")

# bootstrap 刷新周期（秒）
_BOOTSTRAP_REFRESH_S = 24 * 3600

# RDAP 查询超时（秒；whoisit 默认 10s，检测链路单源预算收紧到 5s）
_QUERY_TIMEOUT_S = 5

# 观测计数（queue_stats 同款口径：锁内读写、dict 快照）
_STATS = {
    "total_checked": 0,      # 进入检测的域名数（TLD 过滤后）
    "hits_new": 0,           # 判定新注册数
    "cache_hits": 0,         # 内存/DB 缓存命中数
    "skipped_tld": 0,        # TLD 不在名单被跳过数
    "skipped_unsupported": 0,  # TLD 无 RDAP 服务跳过数
    "skipped_notexist": 0,   # 域名未注册跳过数
    "skipped_error": 0,      # 查询失败跳过数（网络/超时等）
    "rdap_queries": 0,       # 实际发出的 RDAP 网络查询数
}


def stats() -> dict:
    """观测快照（GET /api/nrd/stats 用；零开销）。"""
    with _LOCK:
        return dict(_STATS)


def reset() -> None:
    """复位（测试用：清缓存+计数，不动 bootstrap 状态）。"""
    global _LOADED
    with _LOCK:
        _MEM_CACHE.clear()
        for k in _STATS:
            _STATS[k] = 0
        _LOADED = False


# ---------------------------------------------------------------------------
# TLD 前置过滤
# ---------------------------------------------------------------------------

# （raw 配置串, 解析出的 TLD 集合）进程内缓存：配置未变直接返回集合
_TLD_CACHE: tuple[str, set[str]] = ("", set())


def _tld_set() -> set[str]:
    """解析 nrd_tlds 配置（逗号分隔）→ 小写 TLD 集合（进程内缓存）。"""
    global _TLD_CACHE
    raw = (CONFIG.nrd_tlds or "").strip().lower()
    cached_raw, cached_set = _TLD_CACHE
    if raw == cached_raw:
        return cached_set
    parsed = {t.strip().lstrip(".") for t in raw.split(",") if t.strip()}
    _TLD_CACHE = (raw, parsed)
    return parsed


def _tld_of(domain: str) -> str:
    """取域名 TLD（最后一个标签；已小写无尾点）。"""
    d = (domain or "").rstrip(".").lower()
    return d.rsplit(".", 1)[-1] if "." in d else d


# ---------------------------------------------------------------------------
# 缓存
# ---------------------------------------------------------------------------

def _load_db_cache() -> None:
    """把 nrd_cache 全表载入内存（进程首次调用时执行一次）。

    表设计为"只增不减"（注册时间永不重查），行数 = 历史查得的独立
    域名数，量级可控（NRD 只查高危 TLD，全网活跃高危 TLD 域名对单
    企业网络的基数在万级），全量载入内存无压力。
    """
    global _LOADED
    if _LOADED:
        return
    from app.db import db_cursor
    try:
        with db_cursor() as cur:
            cur.execute("SELECT domain, registered_at FROM nrd_cache")
            rows = cur.fetchall()
        with _LOCK:
            for row in rows:
                try:
                    _MEM_CACHE[row["domain"]] = datetime.fromisoformat(
                        row["registered_at"]).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue          # 脏数据跳过（不致崩溃）
            _LOADED = True
        if rows:
            logger.info("NRD 缓存已加载：%d 条注册时间", len(rows))
    except Exception as e:
        logger.warning("NRD 缓存加载失败（下次调用重试）：%s", e)


def _cache_put(domain: str, registered_at: datetime) -> None:
    """注册时间写内存 + SQLite（永久缓存：只插不改）。"""
    with _LOCK:
        _MEM_CACHE[domain] = registered_at
    try:
        from app.db import db_cursor
        with db_cursor() as cur:
            cur.execute(
                "INSERT OR IGNORE INTO nrd_cache (domain, registered_at) "
                "VALUES (?, ?)",
                (domain, registered_at.strftime("%Y-%m-%dT%H:%M:%SZ")))
    except Exception as e:
        # DB 写失败不影响结论（内存缓存已生效，进程内仍免查）
        logger.warning("NRD 缓存落库失败 %s: %s", domain, e)


# ---------------------------------------------------------------------------
# bootstrap（IANA RDAP 路由表）
# ---------------------------------------------------------------------------

def warm_bootstrap() -> None:
    """预热 whoisit bootstrap：本地缓存优先，过期则拉取 IANA 并落盘。

    后台线程调用（dns_server 启动时 nrd-warmup 线程），不阻塞端口
    就绪。失败只记日志——未就绪时首条查询会同步 bootstrap（拉取
    data.iana.org，约 1~2s），功能不中断。
    """
    global _BOOTSTRAP_READY
    if _BOOTSTRAP_READY or not _HAS_WHOISIT:
        return
    try:
        loaded = False
        # 1) 本地缓存文件（24h 内有效）
        if os.path.exists(_BOOTSTRAP_FILE):
            age_s = time.time() - os.path.getmtime(_BOOTSTRAP_FILE)
            if age_s < _BOOTSTRAP_REFRESH_S:
                try:
                    with open(_BOOTSTRAP_FILE, "r", encoding="utf-8") as f:
                        whoisit.load_bootstrap_data(f.read())
                    loaded = True
                    logger.info("RDAP bootstrap 已从本地缓存加载")
                except Exception as e:
                    logger.warning("RDAP bootstrap 本地缓存加载失败：%s", e)
        # 2) 过期/不存在 → 网络拉取（IANA 官方）并落盘
        if not loaded:
            whoisit.bootstrap()
            _save_bootstrap()
        _BOOTSTRAP_READY = True
    except Exception as e:
        logger.warning("RDAP bootstrap 预热失败（首条查询将同步引导）：%s", e)


def _save_bootstrap() -> None:
    """把当前 bootstrap 数据落盘（原子替换：tmp + os.replace）。"""
    data = whoisit.save_bootstrap_data(as_json=True)
    os.makedirs(os.path.dirname(_BOOTSTRAP_FILE), exist_ok=True)
    tmp = _BOOTSTRAP_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
    os.replace(tmp, _BOOTSTRAP_FILE)
    logger.info("RDAP bootstrap 已拉取并落盘：%s", _BOOTSTRAP_FILE)


def _bootstrap_refresher() -> None:
    """后台 24h 刷新 bootstrap（路由表偶尔增删 RDAP 服务商）。"""
    while True:
        time.sleep(_BOOTSTRAP_REFRESH_S)
        if not _HAS_WHOISIT:
            return
        try:
            whoisit.clear_bootstrapping()
            whoisit.bootstrap()
            _save_bootstrap()
            logger.info("RDAP bootstrap 已刷新（24h 周期）")
        except Exception as e:
            logger.warning("RDAP bootstrap 刷新失败（下轮重试）：%s", e)


def start() -> None:
    """启动后台预热 + 周期刷新线程（dns_server.run_dns_server 调用）。"""
    threading.Thread(target=warm_bootstrap, name="nrd-warmup",
                     daemon=True).start()
    threading.Thread(target=_bootstrap_refresher, name="nrd-bootstrap-refresh",
                     daemon=True).start()


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def is_new_registration(domain: str) -> bool | None:
    """判断域名是否新注册（≤ nrd_max_age_days 天）。

    返回三态：
      True  = 新注册（调用方按 nrd_mode 决定拦截或观察记录）；
      False = 已注册且年龄超过阈值（正常域名）；
      None  = 无结论（TLD 不支持/未注册/查询失败）——**放行**，
              绝不触发 fail-safe（详见模块 docstring 三态语义）。

    主流程调用方式（detectors 4.7 段）：
      if CONFIG.nrd_enabled:
          nrd_hit = rdap_nrd.is_new_registration(domain)
          ...
    """
    d = (domain or "").rstrip(".").lower()
    if not d or not _HAS_WHOISIT:
        return None

    # TLD 前置过滤：名单外域名零开销跳过（.com/.net/.cn 等主流 TLD）
    tlds = _tld_set()
    if tlds and _tld_of(d) not in tlds:
        with _LOCK:
            _STATS["skipped_tld"] += 1
        return None

    _load_db_cache()

    # 缓存命中：注册时间永不重查（域名年龄只增不减）
    with _LOCK:
        cached = _MEM_CACHE.get(d)
        _STATS["total_checked"] += 1
    if cached is not None:
        with _LOCK:
            _STATS["cache_hits"] += 1
        return _age_days(cached) <= CONFIG.nrd_max_age_days

    # RDAP 查询（未预热时同步 bootstrap——正常流程已被 warmup 覆盖）
    try:
        if not _BOOTSTRAP_READY:
            warm_bootstrap()
        # 超时收紧到 5s（默认 10s；检测链路单源预算有限）
        wi_utils.http_timeout = _QUERY_TIMEOUT_S
        with _LOCK:
            _STATS["rdap_queries"] += 1
        result = whoisit.domain(d, follow_related=False)
        reg = result.get("registration_date")
        if not isinstance(reg, datetime):
            # 解析结果无注册时间（少见）：视为无结论
            with _LOCK:
                _STATS["skipped_error"] += 1
            return None
        if reg.tzinfo is None:
            reg = reg.replace(tzinfo=timezone.utc)
        _cache_put(d, reg)
        hit = _age_days(reg) <= CONFIG.nrd_max_age_days
        if hit:
            with _LOCK:
                _STATS["hits_new"] += 1
        return hit
    except wi_errors.UnsupportedError:
        # TLD 无 RDAP 服务（.cn/.local 等）：路由表事实，跳过不误判
        with _LOCK:
            _STATS["skipped_unsupported"] += 1
        return None
    except wi_errors.ResourceDoesNotExist:
        # 域名未注册：跳过（能被查询说明多已注册，多为数据延迟）
        with _LOCK:
            _STATS["skipped_notexist"] += 1
        return None
    except Exception as e:
        # QueryError/RateLimitedError/网络异常：跳过放行，不计熔断失败
        logger.warning("NRD RDAP 查询失败 %s: %s", d, e)
        with _LOCK:
            _STATS["skipped_error"] += 1
        return None


def _age_days(registered_at: datetime) -> int:
    """域名年龄（天，向上取整——注册 1 小时 = 1 天内的新域名）。"""
    delta = datetime.now(timezone.utc) - registered_at
    return max(0, math.ceil(delta.total_seconds() / 86400))
