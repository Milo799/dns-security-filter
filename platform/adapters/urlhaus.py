"""URLhaus（abuse.ch）恶意 URL 分发库适配器 —— 开放 API，免 Key。

- 域名查询: POST https://urlhaus-api.abuse.ch/v1/host/  {host: <domain>}
- IP 查询:   POST https://urlhaus-api.abuse.ch/v1/ip/    {ip: <ip>}
- 响应 query_status: "ok"(命中) / "no_results"(未命中) /
  "invalid_*"/"rate_limit"/"error"(请求问题 → 无结论 None)
- 官方要求限速：查询间隔至少 5 秒（建议更长），因此默认停用，
  由管理员在需要时手动开启（仅用于人工核查场景）。
"""

import logging

import httpx

from adapters import ThreatIntelAdapter, ThreatResult

logger = logging.getLogger("platform.adapters.urlhaus")

API_HOST = "https://urlhaus-api.abuse.ch"


class UrlhausAdapter(ThreatIntelAdapter):
    name = "urlhaus"
    supports_domain = True
    supports_ip = True
    adapter_type = "http"
    is_builtin = True

    def __init__(self, base_url: str = "", api_key: str = "",
                 timeout_ms: int = 2000, config: str = ""):
        super().__init__(base_url=base_url or API_HOST, api_key=api_key,
                         timeout_ms=timeout_ms, config=config)

    def _post(self, path: str, data: dict) -> dict | None:
        url = f"{self.base_url}{path}"
        try:
            resp = httpx.post(url, data=data,
                              headers={"User-Agent": "dns-security-filter/1.0"},
                              timeout=self.timeout_ms / 1000.0,
                              follow_redirects=True)
        except Exception as e:
            logger.info("URLhaus 请求失败 %s: %s", url, e)
            return None
        if resp.status_code != 200:
            logger.info("URLhaus 响应 %s: %s", resp.status_code, resp.text[:200])
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    @staticmethod
    def _parse(data: dict | None, kind: str) -> ThreatResult | None:
        if data is None:
            return None  # 网络失败无结论
        status = data.get("query_status")
        if status == "ok":
            count = len(data.get("urls", [])) if kind == "domain" \
                else len(data.get("urls", []))
            return ThreatResult(True, "urlhaus",
                                f"URLhaus 收录 {count} 条恶意 URL")
        if status == "no_results":
            return ThreatResult(False, "urlhaus", "未命中")
        # invalid_*/rate_limit/error 等 → 请求未成功，无结论
        return None

    def query_domain(self, domain: str) -> ThreatResult | None:
        return self._parse(self._post("/v1/host/", {"host": domain}),
                           "domain")

    def query_ip(self, ip: str) -> ThreatResult | None:
        return self._parse(self._post("/v1/ip/", {"ip": ip}), "ip")
