"""ThreatFox（abuse.ch）僵尸网络 C2 指标适配器 —— 需免费注册 Auth-Key。

C2 专项情报源：收录 botnet C2 服务器、恶意软件分发基础设施等 IOC，
覆盖域名 / IP / URL / ip:port，是 DNS 过滤场景最经典的拦截目标。

- 查询: POST https://threatfox-api.abuse.ch/api/v1/
  Header: Auth-Key: <key>
  Body:   {"query": "search_ioc", "search_term": "<domain|ip>", "exact_match": true}
- 响应 query_status:
  * "ok"           → 命中（data 非空，含 threat_type / malware 家族等）
  * "no_result"    → 未命中
  * 其他（限速/参数错误等）→ 无结论 None
- Key: https://auth.abuse.ch/ 免费注册（fair use 原则，非商业免费）
- 注意：自 2025-05-01 起超过 6 个月的 IOC 会从 API 移除（官方去重策略）
"""

import logging

import httpx

from adapters import ThreatIntelAdapter, ThreatResult

logger = logging.getLogger("platform.adapters.threatfox")

API_HOST = "https://threatfox-api.abuse.ch"


class ThreatFoxAdapter(ThreatIntelAdapter):
    name = "threatfox"
    supports_domain = True
    supports_ip = True
    adapter_type = "http"
    is_builtin = True

    def __init__(self, base_url: str = "", api_key: str = "",
                 timeout_ms: int = 2000, config: str = ""):
        super().__init__(base_url=base_url or API_HOST, api_key=api_key,
                         timeout_ms=timeout_ms, config=config)
        # 允许从 config 的 api_key 字段读 Key（界面编辑 config JSON 亦可）
        self.api_key = self.config.get("api_key") or self.api_key

    def _search(self, term: str) -> dict | None:
        if not self.api_key:
            logger.info("ThreatFox 未配置 Auth-Key，跳过查询 %s", term)
            return None
        url = f"{self.base_url}/api/v1/"
        try:
            resp = httpx.post(
                url,
                headers={"Auth-Key": self.api_key,
                         "User-Agent": "dns-security-filter/1.0"},
                json={"query": "search_ioc", "search_term": term,
                      "exact_match": True},
                timeout=self.timeout_ms / 1000.0,
                follow_redirects=True,
            )
        except Exception as e:
            logger.info("ThreatFox 请求失败 %s: %s", term, e)
            return None
        if resp.status_code != 200:
            logger.info("ThreatFox 响应 %s: %s", resp.status_code,
                        resp.text[:200])
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    @staticmethod
    def _parse(data: dict | None) -> ThreatResult | None:
        if data is None:
            return None  # 网络失败 / 未配置 Key → 无结论
        status = data.get("query_status")
        if status == "ok":
            rows = data.get("data") or []
            if not rows:
                return None  # ok 但无数据，视为异常
            first = rows[0]
            detail = first.get("malware_printable") or \
                first.get("threat_type_desc") or "ThreatFox 收录"
            return ThreatResult(True, "threatfox",
                                f"ThreatFox C2 收录：{detail}")
        if status == "no_result":
            return ThreatResult(False, "threatfox", "未命中")
        # 限速 / 参数错误 / 服务异常 → 无结论
        logger.info("ThreatFox query_status=%s", status)
        return None

    def query_domain(self, domain: str) -> ThreatResult | None:
        return self._parse(self._search(domain))

    def query_ip(self, ip: str) -> ThreatResult | None:
        return self._parse(self._search(ip))
