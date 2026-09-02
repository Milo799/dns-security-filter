"""平台出站 HTTP 统一客户端：情报源查询与大名单下载的唯一网络出口。

设计动机（三层）：

1. **统一网络策略**：所有出站请求强制 IPv4 源地址（local_address="0.0.0.0"）。
   服务器 IPv6 半配置（有接口无路由）时，双栈域名会被 httpx 依次尝试
   AAAA 地址，IPv6 报 [Errno 99] Cannot assign requested address 且掩盖
   IPv4 的真实状态（离线导入 hagezi_ti 失败的根因）。

2. **可选统一代理**：CONFIG.http_proxy 非空时，情报相关出站流量
   （在线情报源 API + 离线大名单下载）全部经代理转发——平台机无法
   直连公网（上联 ACL 只放行有限地址）时，用一台可达的代理机中转。
   代理在 Web 界面配置（system_config 热配置），改地址即时生效
   （重建 Client，无需重启服务）。

3. **修复历史 bug**：httpx 0.28 顶层 httpx.get()/post()/stream() 不接受
   transport= 关键字（直接 TypeError）；此前各适配器直接传 transport
   的写法在 httpx 0.28 环境会让每个请求抛异常（被 except 吞掉表现为
   "源无结论"）。正确做法是经 Client 实例携带 transport / proxy。

注意：
  - DNSBL 类源走 UDP/TCP 53 DNS 协议（dnslib），不经本模块也不经代理；
  - httpx 0.28 的 Client(proxy=...) 会信任标准环境变量（HTTP_PROXY 等），
    本模块显式传 proxy=None 禁用环境代理——出站路径只由 CONFIG.http_proxy
    决定，避免环境变量隐性劫持情报查询流量；
  - 每次请求短连接（连接池复用 httpx 默认行为），代理热更新无需
    关停旧连接。

线程安全：httpx.Client 非线程安全，本模块按"每线程一个 Client"管理
（threading.local），与 db.py 的连接隔离策略一致。
"""

import logging
import threading

import httpx

from config import CONFIG

logger = logging.getLogger("platform.http_client")

# 代理地址允许的 scheme（白名单：只支持显式 http/https 正向代理；
# socks 需要额外依赖 httpx[socks]，不在默认安装范围）
_PROXY_SCHEMES = {"http", "https"}

# 静态 IPv4 强制 transport（无代理时复用，无锁安全）
_IPV4_TRANSPORT = httpx.HTTPTransport(local_address="0.0.0.0")

# 线程本地 Client 缓存：{(proxy or ""): Client}
# 键为代理地址字符串——热切换代理后按新键取/建 Client，
# 旧代理的 Client 惰性留在本线程字典里，线程结束随 local 销毁。
_local = threading.local()


def _current_proxy() -> str:
    """读 CONFIG.http_proxy（热配置），空白视为未启用。"""
    return (getattr(CONFIG, "http_proxy", "") or "").strip()


def _build_client(proxy: str) -> httpx.Client:
    """构建绑定特定代理（或无代理）的 Client；失败降级无代理并告警。"""
    kwargs = {
        "timeout": httpx.Timeout(30.0, connect=15.0),
        "follow_redirects": True,
        # 显式禁用环境变量代理：出站路径只由配置决定
        "proxy": None,
        "transport": _IPV4_TRANSPORT if not proxy else None,
    }
    if proxy:
        kwargs["proxy"] = proxy
        # 代理场景不用本地 transport（HTTPTransport 与 proxy 互斥：
        # Client(proxy=...) 会自建带代理的 transport）
        kwargs.pop("transport")
    client = httpx.Client(**kwargs)
    return client


def _get_client() -> httpx.Client:
    """取当前线程对应现行代理的 Client；代理变更时按需重建。"""
    proxy = _current_proxy()
    cache = getattr(_local, "clients", None)
    if cache is None:
        cache = _local.clients = {}
    client = cache.get(proxy)
    if client is None:
        try:
            client = _build_client(proxy)
        except Exception as e:
            # 典型：代理 URL 格式非法（httpx 解析抛错）——降级直连
            logger.error("HTTP 客户端构建失败（代理 %r），降级直连：%s",
                         proxy, e)
            if proxy:
                return _get_client_for_direct()
            raise
        cache[proxy] = client
        if proxy:
            logger.info("情报出站已启用代理：%s", proxy)
    return client


def _get_client_for_direct() -> httpx.Client:
    """降级直连用的固定键 Client（代理配置非法时不影响直连缓存）。"""
    cache = _local.clients
    client = cache.get("")
    if client is None:
        client = _build_client("")
        cache[""] = client
    return client


def apply_proxy_change() -> None:
    """代理配置变更后的钩子：记录日志（Client 按需惰性重建，无需主动关闭）。

    runtime._apply / cross_sync 调用；保持幂等。
    """
    proxy = _current_proxy()
    if proxy:
        logger.info("情报出站代理已生效：%s（在线情报源与大名单下载均经此代理）", proxy)
    else:
        logger.info("情报出站代理已停用（直连）")


# ---------------------------------------------------------------------------
# 统一请求入口：签名与 httpx 顶层函数保持一致（除 transport/proxy 外），
# 各适配器从 httpx.* 切到 http_client.* 只需改 import 前缀。
# ---------------------------------------------------------------------------

def get(url: str, *, headers: dict | None = None,
        params: dict | None = None, timeout: float | None = None) -> httpx.Response:
    return _get_client().get(url, headers=headers, params=params,
                             timeout=timeout)


def post(url: str, *, data: dict | None = None,
         headers: dict | None = None, timeout: float | None = None) -> httpx.Response:
    return _get_client().post(url, data=data, headers=headers, timeout=timeout)


def stream(url: str, *, headers: dict | None = None,
           timeout: httpx.Timeout | None = None) -> httpx.Response:
    """流式下载上下文管理器（大名单下载用）。

    用法与 httpx.stream 一致：with http_client.stream(...) as resp:
    """
    return _get_client().stream("GET", url, headers=headers, timeout=timeout)


def proxy_status() -> dict:
    """当前代理状态（前端展示/巡检用）。"""
    proxy = _current_proxy()
    return {
        "enabled": bool(proxy),
        "proxy": proxy,
    }
