"""Blocklist.de 攻击源 IP 黑名单适配器 —— 免 Key。

- GET https://api.blocklist.de/api.php?ip=<ip>
- 响应为纯文本：attacks: N<br />reports: N<br />blacklisted: ...<br />
  （N 为攻击/报告次数；未被收录时 attacks 与 reports 均为 0）
- 判定：attacks >= min_attacks → 命中；attacks=0 → 未命中；
  网络失败 / 429 限速 / 文本解析失败 → 无结论 None。
- 覆盖：SSH / 邮件 / Web 暴力破解与扫描攻击源 IP。
- 仅支持 IP 查询（supports_domain=False）。
- 阈值可在 config 调整：{"min_attacks": 1}
"""

import logging
import re

import httpx
from adapters.http_base import _IPV4_TRANSPORT

from adapters import ThreatIntelAdapter, ThreatResult

logger = logging.getLogger("platform.adapters.blocklistde")

API_HOST = "https://api.blocklist.de"
DEFAULT_MIN_ATTACKS = 1


class BlocklistDeAdapter(ThreatIntelAdapter):
    name = "blocklist_de"
    supports_domain = False
    supports_ip = True
    adapter_type = "http"
    is_builtin = True

    def __init__(self, base_url: str = "", api_key: str = "",
                 timeout_ms: int = 2000, config: str = ""):
        super().__init__(base_url=base_url or API_HOST, api_key=api_key,
                         timeout_ms=timeout_ms, config=config)
        self.min_attacks = int(self.config.get("min_attacks",
                                               DEFAULT_MIN_ATTACKS))

    def _lookup(self, ip: str) -> ThreatResult | None:
        url = f"{self.base_url}/api.php?ip={ip}"
        try:
            resp = httpx.get(url,
                             headers={"User-Agent": "dns-security-filter/1.0"},
                             timeout=self.timeout_ms / 1000.0,
                             follow_redirects=True,
                             transport=_IPV4_TRANSPORT)
        except Exception as e:
            logger.info("Blocklist.de 请求失败 %s: %s", url, e)
            return None
        if resp.status_code == 429:
            logger.info("Blocklist.de 限速 429")
            return None
        if resp.status_code != 200:
            logger.info("Blocklist.de 响应 %s: %s",
                        resp.status_code, resp.text[:200])
            return None
        m = re.search(r"attacks:\s*(\d+)", resp.text)
        if not m:
            logger.info("Blocklist.de 无法解析响应: %s", resp.text[:200])
            return None  # 结构异常 → 无结论
        attacks = int(m.group(1))
        if attacks >= self.min_attacks:
            lm = re.search(r"lastreport:\s*([^<]+)", resp.text)
            detail = f"攻击 {attacks} 次"
            if lm:
                detail += f"，最近 {lm.group(1).strip()}"
            return ThreatResult(True, "blocklist_de", detail)
        return ThreatResult(False, "blocklist_de", "未被收录")

    def query_domain(self, domain: str) -> ThreatResult | None:
        # 不支持域名查询（能力声明已为 False，正常流程不会调用）
        return None

    def query_ip(self, ip: str) -> ThreatResult | None:
        return self._lookup(ip)
