"""AlienVault OTX（Open Threat Exchange）威胁情报适配器 —— 需免费注册 API Key。

全球最大的开放威胁情报社区：恶意域名 / IP 量大、覆盖广（恶意软件、钓鱼、
僵尸网络 C2、扫描器等），由安全厂商与社区共同维护，是免费源里体量最可观的。

- 查询: GET https://otx.alienvault.com/api/v1/indicators/{type}/{indicator}/general
  Header: X-OTX-API-KEY: <key>
  域名 → type=domain；IPv4 → type=IPv4；IPv6 → type=IPv6
- 响应 pulse_info.count:
  * count > 0 → 命中（pulses 列表含脉冲名称/描述）
  * count == 0 → 明确未命中
  * HTTP 404（OTX 对未收录 indicator 返回 404）→ 明确未命中
  * 401/403（Key 无效）或其它非 200 / 网络异常 → 无结论 None
- Key: https://otx.alienvault.com/ 免费注册（个人版额度宽松）
"""

import ipaddress
import logging

import httpx
from adapters.http_base import _IPV4_TRANSPORT

from adapters import ThreatIntelAdapter, ThreatResult

logger = logging.getLogger("platform.adapters.otx")

API_HOST = "https://otx.alienvault.com"


class OTXAdapter(ThreatIntelAdapter):
    name = "otx"
    supports_domain = True
    supports_ip = True
    adapter_type = "http"
    is_builtin = True

    def __init__(self, base_url: str = "", api_key: str = "",
                 timeout_ms: int = 2000, config: str = ""):
        super().__init__(base_url=base_url or API_HOST, api_key=api_key,
                         timeout_ms=timeout_ms, config=config)
        self.api_key = self.config.get("api_key") or self.api_key

    @staticmethod
    def _indicator_type(term: str) -> str | None:
        """按查询对象选择 OTX indicator 类型：domain / IPv4 / IPv6。"""
        try:
            addr = ipaddress.ip_address(term)
        except ValueError:
            return "domain"
        return "IPv6" if isinstance(addr, ipaddress.IPv6Address) else "IPv4"

    def _search(self, term: str) -> tuple[int | None, dict | None]:
        """发起查询，返回 (http_status, payload)；网络失败返回 (None, None)。"""
        if not self.api_key:
            logger.info("OTX 未配置 API Key，跳过查询 %s", term)
            return None, None
        itype = self._indicator_type(term)
        url = (f"{self.base_url}/api/v1/indicators/"
               f"{itype}/{httpx.URL(term).path}")
        try:
            resp = httpx.get(
                url,
                headers={"X-OTX-API-KEY": self.api_key,
                         "User-Agent": "dns-security-filter/1.0"},
                timeout=self.timeout_ms / 1000.0,
                follow_redirects=True,
                             transport=_IPV4_TRANSPORT)
        except Exception as e:
            logger.info("OTX 请求失败 %s: %s", term, e)
            return None, None
        if resp.status_code == 404:
            return 404, None  # 未收录 → 明确未命中
        if resp.status_code != 200:
            logger.info("OTX 响应 %s: %s", resp.status_code,
                        resp.text[:200])
            return resp.status_code, None
        try:
            return resp.status_code, resp.json()
        except ValueError:
            return resp.status_code, None

    @staticmethod
    def _parse(status: int | None,
               data: dict | None) -> ThreatResult | None:
        if status == 404:
            return ThreatResult(False, "otx", "OTX 未收录")
        if status != 200 or data is None:
            return None  # 鉴权失败 / 限流 / 网络失败 → 无结论
        pulses = data.get("pulse_info") or {}
        count = pulses.get("count") or 0
        if count <= 0:
            return ThreatResult(False, "otx", "OTX 未命中")
        first = (pulses.get("pulses") or [{}])[0]
        detail = first.get("name") or first.get("description") or "OTX 收录"
        return ThreatResult(True, "otx", f"OTX 收录：{detail}")

    def query_domain(self, domain: str) -> ThreatResult | None:
        return self._parse(*self._search(domain))

    def query_ip(self, ip: str) -> ThreatResult | None:
        return self._parse(*self._search(ip))
