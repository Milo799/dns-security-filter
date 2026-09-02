"""PhishTank（OpenDNS）钓鱼 URL 库适配器 —— 免 Key（app_key 可选）。

- POST https://checkurl.phishtank.com/checkurl/  {url, format=json}
- 响应 JSON：results.in_database = true(命中) / false(未命中)，
  附带 phish_id / verified / valid 等字段。
- 平台按域名构造 URL（https://<domain>/）提交查询。
- app_key 可选：无 Key 限速严格（见响应头 X-Request-Limit），
  适合人工核查 / 低频场景，因此默认停用，建议配合测试中心使用。
- 仅支持域名查询（supports_ip=False）。
"""

import logging

import httpx
from app import http_client

from adapters import ThreatIntelAdapter, ThreatResult

logger = logging.getLogger("platform.adapters.phishtank")

API_HOST = "https://checkurl.phishtank.com"


class PhishTankAdapter(ThreatIntelAdapter):
    name = "phishtank"
    supports_domain = True
    supports_ip = False
    adapter_type = "http"
    is_builtin = True

    def __init__(self, base_url: str = "", api_key: str = "",
                 timeout_ms: int = 2000, config: str = ""):
        super().__init__(base_url=base_url or API_HOST, api_key=api_key,
                         timeout_ms=timeout_ms, config=config)

    def _check(self, url: str) -> ThreatResult | None:
        try:
            resp = http_client.post(f"{self.base_url}/checkurl/",
                              data={"url": url, "format": "json"},
                              headers={"User-Agent": "dns-security-filter/1.0"},
                              timeout=self.timeout_ms / 1000.0)
        except Exception as e:
            logger.info("PhishTank 请求失败 %s: %s", url, e)
            return None
        if resp.status_code == 509:
            # 超出限速，明确无结论（不能当作未命中）
            logger.info("PhishTank 限速 509")
            return None
        if resp.status_code != 200:
            logger.info("PhishTank 响应 %s: %s",
                        resp.status_code, resp.text[:200])
            return None
        try:
            data = resp.json()
        except ValueError:
            logger.info("PhishTank 非 JSON 响应: %s", resp.text[:200])
            return None
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, dict):
            return None  # 结构异常 → 无结论
        in_db = results.get("in_database")
        if in_db is True or str(in_db).lower() in ("true", "1", "y"):
            phish_id = results.get("phish_id")
            detail = f"PhishTank 收录" + (f" phish_id={phish_id}" if phish_id else "")
            return ThreatResult(True, "phishtank", detail)
        if in_db is False or str(in_db).lower() in ("false", "0", "n"):
            return ThreatResult(False, "phishtank", "未命中")
        return None  # 无法识别 → 无结论

    def query_domain(self, domain: str) -> ThreatResult | None:
        return self._check(f"https://{domain}/")

    def query_ip(self, ip: str) -> ThreatResult | None:
        # 不支持 IP 查询（能力声明已为 False，正常流程不会调用）
        return None
