"""SANS DShield（ISC）全球蜜罐攻击源 IP 信誉适配器 —— 免 Key。

- GET https://isc.sans.edu/api/ip/<ip>?json
- 官方要求使用描述性 User-Agent（默认 UA 会被屏蔽）。
- 判定（避免把"被蜜罐扫过一次"就判恶意，采用双条件）：
    count（拦截数据包总数）>= min_count
    且 maxdate（最近被报告日期）距今天数 <= max_age_days
  两者都满足 → 命中（活跃攻击源）；否则 → 未命中。
- count 缺失（该 IP 从未被报告）→ 明确未命中；
  网络失败 / 429 / 结构异常 → 无结论 None。
- 仅支持 IP 查询（supports_domain=False）。
- 阈值可在 Web 界面 config 调整：{"min_count": 500, "max_age_days": 14}
"""

import logging
from datetime import date

import httpx
from adapters.http_base import _IPV4_TRANSPORT

from adapters import ThreatIntelAdapter, ThreatResult

logger = logging.getLogger("platform.adapters.dshield")

API_HOST = "https://isc.sans.edu"
DEFAULT_MIN_COUNT = 500
DEFAULT_MAX_AGE_DAYS = 14


class DShieldAdapter(ThreatIntelAdapter):
    name = "dshield"
    supports_domain = False
    supports_ip = True
    adapter_type = "http"
    is_builtin = True

    def __init__(self, base_url: str = "", api_key: str = "",
                 timeout_ms: int = 2000, config: str = ""):
        super().__init__(base_url=base_url or API_HOST, api_key=api_key,
                         timeout_ms=timeout_ms, config=config)
        self.min_count = int(self.config.get("min_count", DEFAULT_MIN_COUNT))
        self.max_age_days = int(self.config.get("max_age_days",
                                                DEFAULT_MAX_AGE_DAYS))

    def _lookup(self, ip: str) -> ThreatResult | None:
        url = f"{self.base_url}/api/ip/{ip}?json"
        try:
            resp = httpx.get(url,
                             headers={
                                 "User-Agent":
                                     "dns-security-filter/1.0 "
                                     "(threat-intel integration)"},
                             timeout=self.timeout_ms / 1000.0,
                             follow_redirects=True,
                             transport=_IPV4_TRANSPORT)
        except Exception as e:
            logger.info("DShield 请求失败 %s: %s", url, e)
            return None
        if resp.status_code == 429:
            logger.info("DShield 限速 429")
            return None
        if resp.status_code != 200:
            logger.info("DShield 响应 %s: %s", resp.status_code, resp.text[:200])
            return None
        try:
            data = resp.json()
        except ValueError:
            logger.info("DShield 非 JSON 响应: %s", resp.text[:200])
            return None
        ipinfo = data.get("ip") if isinstance(data, dict) else None
        if not isinstance(ipinfo, dict):
            return None  # 结构异常 → 无结论
        count_raw = ipinfo.get("count")
        if count_raw in (None, "", 0, "0"):
            return ThreatResult(False, "dshield", "未被收录")
        try:
            count = int(str(count_raw))
        except (ValueError, TypeError):
            return None
        if count < self.min_count:
            return ThreatResult(
                False, "dshield",
                f"count={count} 低于阈值 {self.min_count}")
        maxdate = str(ipinfo.get("maxdate") or "").strip()
        if not maxdate:
            return None  # 有攻击记录但缺报告日期 → 无结论
        try:
            age = (date.today() - date.fromisoformat(maxdate)).days
        except ValueError:
            return None
        if age > self.max_age_days:
            return ThreatResult(
                False, "dshield",
                f"最近报告 {maxdate}（{age} 天前），已超 {self.max_age_days} 天")
        return ThreatResult(
            True, "dshield",
            f"活跃攻击源 count={count}，最近报告 {maxdate}")

    def query_domain(self, domain: str) -> ThreatResult | None:
        # 不支持域名查询（能力声明已为 False，正常流程不会调用）
        return None

    def query_ip(self, ip: str) -> ThreatResult | None:
        return self._lookup(ip)
