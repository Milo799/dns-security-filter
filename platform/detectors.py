"""DNS 安全过滤平台 - 检测主流程。

对应 PRD「5.1 DNS 请求处理主流程」的 7 步：
  1. 解析报文 → 域名 + QTYPE + 客户端 IP
  2. QTYPE 非 A/AAAA → 直接转发公网解析
  3. 命中白名单 → 直接放行
  4. 域名前置检测（本地黑名单 + 威胁情报多源融合）
  5. 请求公网 DNS 解析
  6. IP 后置过滤（逐条校验）
  7. 构造应答返回

【状态说明】本文件已完成"最小可用链路"：
  本地黑白名单、公网解析、IP 后置（本地黑名单）、拦截/放行应答、日志写入。
【AI 开发指引】以下功能仍待完善（标 TODO(AI)）：
  1. query_threatintel_domain/ip 的适配器并发调用（当前为串行）
  2. 真实威胁情报源适配器（adapters/ 目录）
  3. EDNS0 Client Subnet 客户端 IP 提取（dns_server.extract_client_ip）
"""

import ipaddress
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from dnslib import DNSRecord, QTYPE, RR, A, AAAA, RCODE

import domain_cache
import ip_cache
import circuit_breaker
import log_writer
from config import CONFIG
from app.db import db_cursor, get_enabled_list
from app.threat_list import check_domain, check_ip
from adapters import get_enabled_adapters, run_fusion

logger = logging.getLogger("platform.detectors")

# QTYPE 支持过滤检测的类型：A / AAAA 同等处理
FILTERABLE_TYPES = {QTYPE.A, QTYPE.AAAA}


def extract_ptr_ip(ptr_name: str) -> str | None:
    """从 PTR 查询名（in-addr.arpa / ip6.arpa）提取 IP，失败返回 None。

    - IPv4：4.3.2.1.in-addr.arpa → 1.2.3.4
    - IPv6：32 个半字节反转 + .ip6.arpa → 压缩格式 IPv6 地址
    """
    name = (ptr_name or "").rstrip(".").lower()
    if name.endswith(".in-addr.arpa"):
        labels = name[: -len(".in-addr.arpa")].split(".")
        if len(labels) != 4:
            return None
        if not all(l.isdigit() and 0 <= int(l) <= 255 for l in labels):
            return None
        return ".".join(reversed(labels))
    if name.endswith(".ip6.arpa"):
        nibbles = name[: -len(".ip6.arpa")].split(".")
        if len(nibbles) != 32:
            return None
        if not all(len(n) == 1 and n in "0123456789abcdef" for n in nibbles):
            return None
        hex_str = "".join(reversed(nibbles))          # 32 个十六进制字符
        groups = [hex_str[i:i + 4] for i in range(0, 32, 4)]
        try:
            return str(ipaddress.IPv6Address(":".join(groups)))
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------------------
# 1. 名单匹配（白名单 / 黑名单）
# ---------------------------------------------------------------------------

def _match_domain(domain: str, patterns: list[str]) -> bool:
    """域名匹配：精确匹配 + 通配符（*.xxx.com 匹配 a.xxx.com、a.b.xxx.com）。"""
    d = domain.rstrip(".")
    for p in patterns:
        p = p.strip().rstrip(".")
        if not p:
            continue
        if p.startswith("*."):
            suffix = p[2:]
            if d == suffix or d.endswith("." + suffix):
                return True
        elif d == p:
            return True
    return False


def _match_ip(ip: str, patterns: list[str]) -> bool:
    """IP 匹配：精确 IP 与 CIDR 网段（10.0.0.0/24），IPv4/IPv6 均适用。"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for p in patterns:
        p = p.strip()
        if not p:
            continue
        if "/" in p:
            try:
                if addr in ipaddress.ip_network(p, strict=False):
                    return True
            except ValueError:
                continue
        elif p == ip:
            return True
    return False


def is_whitelisted(domain: str) -> bool:
    """白名单命中即跳过全部检测直接放行（优先级最高）。"""
    return _match_domain(domain, get_enabled_list("whitelist", "domain"))


def is_blacklisted(domain: str) -> bool:
    """本地域名黑名单判断。"""
    return _match_domain(domain, get_enabled_list("blacklist", "domain"))


def is_ip_blacklisted(ip: str) -> bool:
    """本地 IP 黑名单（含 CIDR）。"""
    return _match_ip(ip, get_enabled_list("blacklist", "ip"))


# ---------------------------------------------------------------------------
# 2. 威胁情报多源集成与融合（对应 PRD 5.3）
# ---------------------------------------------------------------------------

def query_threatintel_domain(domain: str) -> tuple[bool, str]:
    """并发调用启用的威胁情报适配器查询域名，按 fusion_strategy 判定恶意。

    返回 (is_malicious, reason)：
      reason 形如 "threatintel:any:virustotal,abuseipdb"。

    规则（PRD 5.3）：
      - 只调用声明 supports_domain 的启用源（如 AbuseIPDB 不支持域名查询）；
      - 没有任何源支持域名查询 → 跳过威胁情报检测（返回 False）；
      - 超时/异常（None）的源不参与统计；
      - any（默认）/ majority / all 三种融合策略；
      - 有支持源但全部无结论时**默认拦截**，不自动放行（fail-safe）。

    并发实现：线程池并发查询（适配器为同步阻塞 IO），
    总耗时 ≈ 最慢源的单源耗时（api_timeout_ms），而非逐源累加。

    结论缓存（10 万终端前置开发项 1）：TTL+LRU（domain_cache 模块）。
    重复查询同一域名直接回缓存结论，跳过全部在线查询；
    情报源配置/融合策略变更时由路由层清空（threatintel_invalidate）。
    **fail-safe 默认拦截不写缓存**（reason 以 "threatintel:" 前缀且来自
    全源无结论的路径）——缓存瞬时故障会放大为持续误拦。

    熔断降级（10 万终端前置开发项 2，circuit_breaker 模块）：
    - 源级熔断：连续失败 N 次的源跳过调用（open），冷却后半开探测恢复；
    - 路径级降级：failsafe_mode=degrade 时，连续 fail-safe 达阈值开
      降级窗口——窗口内本函数直接返回 (False, "degraded")，本地名单/
      离线大名单/IP 后置仍正常执行（安全底线不破）；
      failsafe_mode=intercept（默认）保持原 fail-safe 拦截语义。
    """
    # 命中缓存：直接返回结论（含恶意与放行两类；缓存结论来自源健康期，
    # 降级窗口内仍然有效——恶意域名不因降级而放过）
    cached = domain_cache.get(domain)
    if cached is not None:
        return cached

    # 降级窗口：在线情报整体跳过（本地黑名单/大名单已在主流程前置执行）
    if circuit_breaker.is_degraded():
        return False, "degraded"

    adapters = [a for a in get_enabled_adapters() if a.supports_domain]
    if not adapters:
        return False, ""  # 无支持域名查询的情报源：跳过威胁情报检测

    # 源级熔断：跳过 open 态故障源（冷却到期的转 half-open 放行探测）
    adapters = [a for a in adapters if circuit_breaker.allows_source(a.name)]
    if not adapters:
        # 全部源都被熔断：等价全源无结论 → 走 fail-safe 语义（含降级判断）
        circuit_breaker.record_failsafe()
        return _failsafe_verdict([])

    def _safe_query(adapter):
        try:
            return adapter.query_domain(domain)
        except Exception as e:
            logger.warning("情报源 %s 查询域名异常: %s", adapter.name, e)
            return None

    with ThreadPoolExecutor(max_workers=min(len(adapters), 12)) as pool:
        raw = list(pool.map(_safe_query, adapters))
    # 熔断计数：None（无结论/异常）计失败，有结论（含未命中）计成功
    for adapter, r in zip(adapters, raw):
        if r is None:
            circuit_breaker.record_failure(adapter.name)
        else:
            circuit_breaker.record_success(adapter.name)
    results = [r for r in raw if r is not None]

    srcs = ",".join(a.name for a in adapters)
    if not results:
        # 全部源超时/故障（无任何结论）→ fail-safe（拦截或降级，均不写缓存）
        circuit_breaker.record_failsafe()
        return _failsafe_verdict(adapters)

    circuit_breaker.record_verdict()
    malicious = run_fusion(results, CONFIG.fusion_strategy)
    srcs = ",".join(r.source for r in results)
    reason = f"threatintel:{CONFIG.fusion_strategy}:{srcs}"
    domain_cache.put(domain, malicious, reason)   # 有结论（含放行）→ 写缓存
    return malicious, reason


def _failsafe_verdict(adapters) -> tuple[bool, str]:
    """fail-safe 分支统一出口：按 failsafe_mode 决定拦截或降级放行。

    intercept（默认）: (True, "threatintel:<strategy>:<srcs>")——默认拦截；
    degrade          : (False, "degraded:failsafe")——降级放行（不写缓存）。
    adapters 仅供 reason 组装（可为空列表，如全源熔断场景）。
    """
    if circuit_breaker.failsafe_mode() == "degrade":
        return False, "degraded:failsafe"
    srcs = ",".join(a.name for a in adapters)
    return True, f"threatintel:{CONFIG.fusion_strategy}:{srcs}"


def query_threatintel_ip(ip: str) -> tuple[bool, str]:
    """对单个 IP（IPv4/IPv6）执行威胁情报融合判断，返回 (is_malicious, reason)。

    逻辑与 query_threatintel_domain 一致（线程池并发），仅调用声明 supports_ip 的适配器。

    结论缓存（ip_cache，TTL+LRU）：热门域名应答 IP 高度集中（CDN Top IP
    覆盖绝大多数流量），重复 IP 直接回缓存结论跳过全部在线查询；
    情报源配置/融合策略变更时由路由层 threatintel_invalidate 一并清空。
    **fail-safe 默认拦截不写缓存**（全源无结论不代表情报判定，与
    domain_cache 同规则——缓存瞬时故障会放大为持续误拦）。
    """
    cached = ip_cache.get(ip)
    if cached is not None:
        return cached

    adapters = [a for a in get_enabled_adapters() if a.supports_ip]
    if not adapters:
        return False, ""  # 无支持 IP 查询的情报源：跳过威胁情报检测

    # 源级熔断：跳过 open 态故障源（与域名路径同规则）
    adapters = [a for a in adapters if circuit_breaker.allows_source(a.name)]
    if not adapters:
        circuit_breaker.record_failsafe()
        return _failsafe_verdict_ip([])

    def _safe_query(adapter):
        try:
            return adapter.query_ip(ip)
        except Exception as e:
            logger.warning("情报源 %s 查询 IP 异常: %s", adapter.name, e)
            return None

    with ThreadPoolExecutor(max_workers=min(len(adapters), 12)) as pool:
        raw = list(pool.map(_safe_query, adapters))
    # 熔断计数：None（无结论/异常）计失败，有结论（含未命中）计成功
    for adapter, r in zip(adapters, raw):
        if r is None:
            circuit_breaker.record_failure(adapter.name)
        else:
            circuit_breaker.record_success(adapter.name)
    results = [r for r in raw if r is not None]

    if not results:
        # 全部源超时/故障（无任何结论）→ fail-safe（不写缓存）
        circuit_breaker.record_failsafe()
        return _failsafe_verdict_ip(adapters)

    circuit_breaker.record_verdict()
    malicious = run_fusion(results, CONFIG.fusion_strategy)
    srcs = ",".join(r.source for r in results)
    reason = f"threatintel:{CONFIG.fusion_strategy}:{srcs}"
    ip_cache.put(ip, malicious, reason)     # 有结论（含放行）→ 写缓存
    return malicious, reason


def _failsafe_verdict_ip(adapters) -> tuple[bool, str]:
    """IP 路径的 fail-safe 分支出口（与 _failsafe_verdict 同语义）。"""
    if circuit_breaker.failsafe_mode() == "degrade":
        return False, "degraded:failsafe"
    srcs = ",".join(a.name for a in adapters)
    return True, f"threatintel:{CONFIG.fusion_strategy}:{srcs}"


# ---------------------------------------------------------------------------
# 3. 公网解析
# ---------------------------------------------------------------------------

def _qtype_name(qtype: int) -> str:
    if qtype == QTYPE.A:
        return "A"
    if qtype == QTYPE.AAAA:
        return "AAAA"
    if qtype == QTYPE.PTR:
        return "PTR"
    return str(qtype)


def _upstream_target() -> tuple[str, int]:
    """解析公网 DNS 地址，支持 'ip' 或 'ip:port' 形式。"""
    value = CONFIG.upstream_dns.strip()
    if ":" in value:
        host, _, port = value.rpartition(":")
        return host, int(port)
    return value, 53


def query_upstream(domain: str, qtype: int) -> list[str]:
    """请求公网 DNS（CONFIG.upstream_dns）解析域名，返回 IP 列表。

    - A 查询得 IPv4 列表；AAAA 查询得 IPv6 列表
    - 解析失败返回空列表（不缓存，避免投毒与一致性问题）
    """
    host, port = _upstream_target()
    try:
        q = DNSRecord.question(domain, _qtype_name(qtype))
        # 注意：dnslib 的 send() 返回原始 bytes，需 parse 后再访问 .rr
        data = q.send(host, port, timeout=3)
        resp = DNSRecord.parse(data)
        return [str(rr.rdata) for rr in resp.rr if rr.rtype == qtype]
    except Exception as e:
        logger.warning("公网解析失败 %s(%s): %s", domain, _qtype_name(qtype), e)
        return []


def query_upstream_reply(request: DNSRecord) -> DNSRecord:
    """向公网 DNS 发起与请求相同的问题，返回原始应答（EDNS0 由 dnslib 保持）。

    失败时返回 SERVFAIL。
    TODO(AI): 大响应（TC 置位）时需走 TCP 重试。
    """
    host, port = _upstream_target()
    try:
        # 注意：dnslib 的 send() 返回原始 bytes，需 parse 后再返回
        data = request.send(host, port, timeout=3)
        return DNSRecord.parse(data)
    except Exception as e:
        logger.warning("上游转发失败: %s", e)
        reply = request.reply()
        reply.header.rcode = RCODE.SERVFAIL
        return reply


def _extract_ips(reply: DNSRecord, qtype: int) -> list[str]:
    """从上游原始应答提取指定类型的 IP 列表（供 IP 后置过滤用）。"""
    try:
        return [str(rr.rdata) for rr in reply.rr if rr.rtype == qtype]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# 4. IP 后置过滤
# ---------------------------------------------------------------------------

def ip_postfilter(ips: list[str]) -> tuple[list[str], list[str]]:
    """对解析结果 IP 逐条校验，返回 (保留IP列表, 恶意IP列表)。

    - 命中本地 IP 黑名单（含 CIDR）→ 剔除（纯内存，不并发）
    - 威胁情报融合判定恶意（声明 supports_ip 的启用源）→ 剔除
      IP 缓存命中直接返回；未命中的 IP 线程池并行查询（多 IP 应答
      时总耗时 ≈ 单 IP 耗时，而非逐 IP 累加）。
    """
    kept, malicious = [], []
    # 先过本地黑名单（纯内存 O(1)），需在线查询的进入并行批次
    pending = []
    for ip in ips:
        if is_ip_blacklisted(ip):
            malicious.append(ip)
        else:
            pending.append(ip)

    if not pending:
        return kept, malicious

    def _check(ip: str) -> bool:
        bad, _ = query_threatintel_ip(ip)
        return bad

    # 单 IP 无需线程池开销，直接查
    if len(pending) == 1:
        results = {pending[0]: _check(pending[0])}
    else:
        with ThreadPoolExecutor(max_workers=min(len(pending), 8)) as pool:
            results = dict(zip(pending, pool.map(_check, pending)))

    for ip in pending:
        if results[ip]:
            malicious.append(ip)
        else:
            kept.append(ip)
    return kept, malicious


# ---------------------------------------------------------------------------
# 5. 应答构造
# ---------------------------------------------------------------------------

def build_intercept_reply(request: DNSRecord, qtype: int) -> DNSRecord:
    """构造拦截应答（对应 PRD 5.4）。

    - A 查询：ANSWER 返回固定告警 IP（CONFIG.alert_ip，TTL=alert_ttl）
    - AAAA 查询：返回空应答（RCODE=NOERROR，ANSWER 为空），客户端无 IPv6 可用
    - 不返回 NXDOMAIN、不丢弃报文
    """
    reply = request.reply()
    reply.header.rcode = RCODE.NOERROR
    qname = request.q.qname
    if qtype == QTYPE.A:
        reply.add_answer(RR(qname, QTYPE.A, ttl=CONFIG.alert_ttl,
                            rdata=A(CONFIG.alert_ip)))
    return reply


def build_remaining_reply(request: DNSRecord, qtype: int,
                          remaining_ips: list[str]) -> DNSRecord:
    """用剩余正常 IP 构造应答（发生部分剔除时使用）。"""
    reply = request.reply()
    reply.header.rcode = RCODE.NOERROR
    qname = request.q.qname
    if qtype == QTYPE.A:
        for ip in remaining_ips:
            reply.add_answer(RR(qname, QTYPE.A, ttl=CONFIG.alert_ttl, rdata=A(ip)))
    elif qtype == QTYPE.AAAA:
        for ip in remaining_ips:
            reply.add_answer(RR(qname, QTYPE.AAAA, ttl=CONFIG.alert_ttl,
                                rdata=AAAA(ip)))
    return reply


# ---------------------------------------------------------------------------
# 6. 日志记录
# ---------------------------------------------------------------------------

def write_filter_log(client_ip: str, domain: str, qtype: int,
                     reason: str, action: str, malicious_ips: list[str],
                     final_result: str, source_api: str = "") -> None:
    """写过滤日志（被拦截/被剔除的记录，PRD 5.5 必录字段）。

    前置项 5（写入削峰）：经 log_writer 异步入队，检测线程不与
    SQLite 写锁竞争（log_async_enabled=0 时回退同步直写）。
    """
    log_writer.enqueue(client_ip, domain, _qtype_name(qtype), reason,
                       action, ",".join(malicious_ips), final_result,
                       source_api)


_ALLOW_LOG_SEQ = [0]
_ALLOW_LOG_SEQ_LOCK = threading.Lock()


def _allow_log_sampled() -> bool:
    """放行日志是否被本次采样命中（前置项 4）。

    rate=100 全录；rate=0 等价关闭；0<rate<100 按百分比采样。
    计数取模实现确定性采样（无 random 线程安全开销），
    任意连续 100 次调用命中数恰为 rate。
    """
    rate = CONFIG.allow_log_sample_rate
    if rate >= 100:
        return True
    if rate <= 0:
        return False
    with _ALLOW_LOG_SEQ_LOCK:
        _ALLOW_LOG_SEQ[0] = (_ALLOW_LOG_SEQ[0] + 1) % 100
        seq = _ALLOW_LOG_SEQ[0]
    return seq < rate


def write_allow_log(client_ip: str, domain: str, qtype: int) -> None:
    """写放行日志（可选：allow_log_enabled 开启且采样命中时记录）。

    10 万终端全量放行日志每日数百万行——采样率把量压到可运维水平；
    拦截/剔除日志属安全事件，永远必录不采样（write_filter_log）。
    """
    if not _allow_log_sampled():
        return
    log_writer.enqueue(client_ip, domain, _qtype_name(qtype),
                       "allow", "allow", "", "forwarded", "")


# ---------------------------------------------------------------------------
# 7. 主流程
# ---------------------------------------------------------------------------

def process_query(request: DNSRecord, client_ip: str | None = None) -> DNSRecord:
    """检测主流程入口。返回应答报文（dnslib.DNSRecord）。"""
    q = request.q
    domain = str(q.qname).rstrip(".")
    qtype = q.qtype

    # 检测总开关（PRD：管理员可临时关闭全部检测以放行）
    if not CONFIG.detection_enabled:
        return query_upstream_reply(request)

    # 1) PTR 反向解析：按查询的 IP 过滤（白名单→黑名单→威胁情报），不能漏
    if qtype == QTYPE.PTR:
        return _process_ptr(request, domain, client_ip or "")

    # 2) 非 A/AAAA → 直接转发公网解析（不做过滤）
    if qtype not in FILTERABLE_TYPES:
        return query_upstream_reply(request)

    # 3) 白名单 → 直接放行（写放行日志，若开启）
    if is_whitelisted(domain):
        if CONFIG.allow_log_enabled:
            write_allow_log(client_ip or "", domain, qtype)
        return query_upstream_reply(request)

    # 4) 域名前置检测
    if is_blacklisted(domain):
        write_filter_log(client_ip or "", domain, qtype,
                         "local_blacklist", "intercept", [],
                         "alert_ip:" + CONFIG.alert_ip)
        return build_intercept_reply(request, qtype)

    # 4.5) 离线大名单命中（hagezi/StevenBlack 等导入源，零 API 依赖）
    if check_domain(domain):
        write_filter_log(client_ip or "", domain, qtype,
                         "threat_list", "intercept", [],
                         "alert_ip:" + CONFIG.alert_ip)
        return build_intercept_reply(request, qtype)

    malicious, reason = query_threatintel_domain(domain)
    if malicious:
        write_filter_log(client_ip or "", domain, qtype,
                         reason, "intercept", [],
                         "alert_ip:" + CONFIG.alert_ip)
        return build_intercept_reply(request, qtype)

    # 5) 公网解析（单次往返）→ IP 后置过滤
    #    拿上游原始应答一次，从中提取 IP 做后置过滤：
    #    全正常直接返回该应答（保留上游 TTL/EDNS0 等原语，省一次重复解析）
    upstream_reply = query_upstream_reply(request)
    if upstream_reply.header.rcode != RCODE.NOERROR:
        return upstream_reply          # SERVFAIL/NXDOMAIN 原样透传上游结论
    ips = _extract_ips(upstream_reply, qtype)
    if not ips:
        # 上游无应答记录（如 AAAA 无 IPv6）：原样返回，不拦截不误报
        return upstream_reply

    kept, malicious_ips = ip_postfilter(ips)
    if not kept:
        # 全部恶意 → 拦截应答
        final = "empty" if qtype == QTYPE.AAAA else "alert_ip:" + CONFIG.alert_ip
        write_filter_log(client_ip or "", domain, qtype,
                         "ip_filter", "intercept", malicious_ips, final)
        return build_intercept_reply(request, qtype)
    if len(kept) < len(ips):
        # 部分恶意 → 剔除恶意、保留正常（写日志）
        final = "remaining_ips:" + ",".join(kept)
        write_filter_log(client_ip or "", domain, qtype,
                         "ip_filter", "remove_ip", malicious_ips, final)
        return build_remaining_reply(request, qtype, kept)

    # 6) 全部正常 → 返回上游原始应答（已在第 5 步取得，不再重复解析）
    return upstream_reply


def _process_ptr(request: DNSRecord, ptr_name: str, client_ip: str) -> DNSRecord:
    """PTR 反向解析过滤：从查询名提取 IP，按 IP 走白名单→黑名单→威胁情报。

    - 非标准 PTR 名（无法提取 IP）→ 直接转发上游，不误拦；
    - 白名单 IP 命中 → 放行（最高优先级）；
    - 本地 IP 黑名单命中 / 威胁情报判定恶意 → 拦截（空应答 NOERROR）；
    - 拦截记录写过滤日志（domain 存 PTR 查询名，malicious_ips 存提取的 IP）。
    """
    ip = extract_ptr_ip(ptr_name)
    if ip is None:
        return query_upstream_reply(request)

    if _match_ip(ip, get_enabled_list("whitelist", "ip")):
        if CONFIG.allow_log_enabled:
            write_allow_log(client_ip, ptr_name, QTYPE.PTR)
        return query_upstream_reply(request)

    if _match_ip(ip, get_enabled_list("blacklist", "ip")):
        write_filter_log(client_ip, ptr_name, QTYPE.PTR, "local_blacklist",
                         "intercept", [ip], "empty")
        return build_intercept_reply(request, QTYPE.PTR)

    if check_ip(ip):
        write_filter_log(client_ip, ptr_name, QTYPE.PTR, "threat_list",
                         "intercept", [ip], "empty")
        return build_intercept_reply(request, QTYPE.PTR)

    bad, reason = query_threatintel_ip(ip)
    if bad:
        write_filter_log(client_ip, ptr_name, QTYPE.PTR, reason,
                         "intercept", [ip], "empty")
        return build_intercept_reply(request, QTYPE.PTR)

    return query_upstream_reply(request)
