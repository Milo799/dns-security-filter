"""DNSBL（DNS 黑名单）威胁情报适配器 —— 开源免 Key，开箱即用。

原理：通过标准 DNS A 记录查询判断 IP/域名是否被列入黑名单。
  - IP 查询：查询 <反转IPv4>.<zone> 的 A 记录（如 4.3.2.1.zen.spamhaus.org）
  - 域名查询：查询 <domain>.<zone> 的 A 记录（如 example.com.dbl.spamhaus.org）
  - 应答为 127.0.0.0/8 网段 → 命中（LISTED），具体返回码含义见各源 code_map
  - NXDOMAIN / 无 A 记录 → 明确未命中
  - 网络失败 / 超时 → 返回 None（无结论，参与 fail-safe 默认拦截）

特性：
  - 不需要 API Key，无需申请；
  - 通过 UDP/TCP 53 直接查询，天然契合 DNS 过滤平台架构；
  - resolver 可配置（默认 8.8.8.8），可按部署网络调整。
"""

import logging

from dnslib import DNSRecord, QTYPE

from adapters import ThreatIntelAdapter, ThreatResult

logger = logging.getLogger("platform.adapters.dnsbl")


class DNSBLAdapter(ThreatIntelAdapter):
    """DNSBL 基类：子类只需定义 name/zone/supports_*/code_map。"""

    name = ""
    zone = ""                      # 查询 zone，如 zen.spamhaus.org
    supports_domain: bool = False
    supports_ip: bool = False
    adapter_type = "dnsbl"
    code_map: dict[str, str] = {}  # 127.0.0.x 返回码 → 含义

    def __init__(self, base_url: str = "", api_key: str = "",
                 timeout_ms: int = 2000, config: str = ""):
        super().__init__(base_url=base_url, api_key=api_key,
                         timeout_ms=timeout_ms, config=config)
        self.zone = self.config.get("zone") or self.zone
        self.resolver = self.config.get("resolver") or "8.8.8.8"

    # ---- 查询原语 ----

    def _lookup(self, fqdn: str) -> list[str] | None:
        """向公共 DNS 查询 A 记录。

        返回：命中的 A 记录 IP 列表；未命中返回 []；网络失败/超时返回 None。
        """
        try:
            q = DNSRecord.question(fqdn, "A")
            data = q.send(self.resolver, 53, timeout=self.timeout_ms / 1000.0)
            resp = DNSRecord.parse(data)
            return [str(rr.rdata) for rr in resp.rr if rr.rtype == QTYPE.A]
        except Exception as e:
            logger.info("DNSBL %s 查询 %s 失败: %s", self.name, fqdn, e)
            return None

    @staticmethod
    def _reverse_ipv4(ip: str) -> str | None:
        parts = ip.split(".")
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255
                                      for p in parts):
            return None
        return ".".join(reversed(parts))

    # Spamhaus 公共解析器限流/拒答专用码：出现即视为"无结论"（fail-safe），
    # 绝不能当成命中——否则 Google/阿里等公共 DNS 大量查询时会造成大面积误拦
    _NO_ANSWER_CODES = {"127.255.255.254", "127.255.255.252"}

    # 忽略码（类属性，子类可覆盖）：命中这些返回码不算恶意——
    # PBL（127.0.0.10/11）是"动态/非邮件 IP 段"邮件发送策略清单，语义是
    # "该 IP 不应直接发邮件"，不是恶意主机；国内运营商 CDN IP 大量被列
    # （实测 www.126.com/www.163.com/www.baidu.com 的 CDN 节点全部踩 PBL），
    # 用它拦截浏览类流量必然大面积误拦。默认全部 DNSBL 子类忽略 PBL 码；
    # 需要邮件场景严格策略时在源 config 里设 ignore_pbl: false
    _IGNORE_CODES: set[str] = set()

    def _verdict(self, ips: list[str] | None) -> ThreatResult | None:
        """将 DNSBL 应答翻译为统一结果。"""
        if ips is None:
            return None  # 网络失败无结论
        # 先排除限流/拒答码（127.255.255.252/254），它们不是命中
        hits = [ip for ip in ips
                if ip.startswith("127.") and ip not in self._NO_ANSWER_CODES]
        if hits:
            code = hits[0]
            if code in self._IGNORE_CODES and self.config.get("ignore_pbl", True):
                return ThreatResult(False, self.name,
                                    f"LISTED {code}（命中忽略码，不计恶意）")
            meaning = self.code_map.get(code, "命中黑名单")
            return ThreatResult(True, self.name,
                                f"LISTED {code}（{meaning}）")
        if any(ip in self._NO_ANSWER_CODES for ip in ips):
            logger.warning(
                "DNSBL %s 返回 127.255.255.25x（公共解析器限流/拒答，"
                "建议把该源 resolver 换成非公共 DNS 或减少查询量）",
                self.name)
            return None  # 无结论，参与 fail-safe
        return ThreatResult(False, self.name, "未命中")

    # ---- 能力实现 ----

    def query_domain(self, domain: str) -> ThreatResult | None:
        if not self.supports_domain:
            return ThreatResult(False, self.name, "该源不支持域名查询")
        fqdn = f"{domain.rstrip('.')}.{self.zone}"
        return self._verdict(self._lookup(fqdn))

    def query_ip(self, ip: str) -> ThreatResult | None:
        if not self.supports_ip:
            return ThreatResult(False, self.name, "该源不支持 IP 查询")
        if ":" in ip:  # IPv6：DNSBL 反查机制不适用，明确未命中（避免 fail-safe 误杀）
            return ThreatResult(False, self.name, "DNSBL 仅支持 IPv4 反查")
        rev = self._reverse_ipv4(ip)
        if rev is None:
            return ThreatResult(False, self.name, f"非法 IPv4：{ip}")
        return self._verdict(self._lookup(f"{rev}.{self.zone}"))


# ---------------------------------------------------------------------------
# 内置开源源（返回码含义参考各项目官方文档）
# ---------------------------------------------------------------------------

class SpamhausZenAdapter(DNSBLAdapter):
    """Spamhaus ZEN：综合 IP 信誉（SBL 僵尸/垃圾 + XBL 被劫持 + PBL 动态段）。

    PBL 返回码（127.0.0.10/11）默认忽略不计恶意——见基类 _IGNORE_CODES 注释：
    国内运营商 CDN IP 大面积被列 PBL（邮件发送策略清单，非恶意主机清单），
    直接用于浏览类 DNS 拦截会误杀主流站点（实测 126/163/baidu CDN 全踩 PBL）。
    邮件场景需严格策略时在源 config 加 "ignore_pbl": false。
    """
    name = "spamhaus_zen"
    zone = "zen.spamhaus.org"
    supports_domain = False
    supports_ip = True
    _IGNORE_CODES = {"127.0.0.10", "127.0.0.11"}
    code_map = {
        "127.0.0.2": "SBL 僵尸网络/垃圾邮件",
        "127.0.0.3": "SBL CSS 僵尸网络子段",
        "127.0.0.4": "XBL 被劫持主机（木马/病毒）",
        "127.0.0.5": "XBL CBL 被劫持主机",
        "127.0.0.6": "XBL CBL 被劫持主机",
        "127.0.0.7": "XBL CBL 被劫持主机",
        "127.0.0.10": "PBL 动态/非邮件 IP 段",
        "127.0.0.11": "PBL 动态/非邮件 IP 段",
    }


class SpamhausDBLAdapter(DNSBLAdapter):
    """Spamhaus DBL：域名黑名单（垃圾/钓鱼/恶意软件分发/僵尸 C&C）。"""
    name = "spamhaus_dbl"
    zone = "dbl.spamhaus.org"
    supports_domain = True
    supports_ip = False
    code_map = {
        "127.0.1.2": "垃圾邮件域名",
        "127.0.1.4": "钓鱼域名",
        "127.0.1.5": "恶意软件分发域名",
        "127.0.1.6": "僵尸网络 C&C 域名",
        "127.0.1.102": "垃圾邮件域名（子域命中）",
        "127.0.1.104": "钓鱼域名（子域命中）",
        "127.0.1.105": "恶意软件域名（子域命中）",
        "127.0.1.106": "僵尸 C&C 域名（子域命中）",
    }


class DroneBLAdapter(DNSBLAdapter):
    """DroneBL：僵尸网络/滥用 IP（垃圾、暴力破解、恶意软件、代理等）。"""
    name = "dronebl"
    zone = "dnsbl.dronebl.org"
    supports_domain = False
    supports_ip = True
    code_map = {
        "127.0.0.2": "垃圾邮件发送",
        "127.0.0.3": "暴力破解",
        "127.0.0.4": "恶意软件/僵尸网络",
        "127.0.0.5": "开放代理",
        "127.0.0.6": "IRC 僵尸",
        "127.0.0.7": "DDoS 参与",
        "127.0.0.8": "端口扫描",
        "127.0.0.9": "钓鱼",
        "127.0.0.10": "广告追踪",
        "127.0.0.11": "IRC 滥用",
        "127.0.0.12": "流量劫持",
        "127.0.0.13": "暗网/恶意软件下载",
        "127.0.0.14": "恶意软件分发",
        "127.0.0.15": "僵尸网络（其他）",
        "127.0.0.16": "恶意软件（其他）",
        "127.0.0.17": "暴力破解（SSH 等）",
        "127.0.0.18": "垃圾邮件（其他）",
        "127.0.0.19": "Web 攻击",
        "127.0.0.255": "全部类别",
    }


class SPFBLAdapter(DNSBLAdapter):
    """SPFBL：综合垃圾/恶意域名与 IP 黑名单。"""
    name = "spfbl"
    zone = "dnsbl.spfbl.net"
    supports_domain = True
    supports_ip = True
    code_map = {
        "127.0.0.2": "垃圾邮件/滥用",
        "127.0.0.3": "恶意软件",
        "127.0.0.4": "钓鱼",
        "127.0.0.5": "僵尸网络",
    }
