"""微步在线 ThreatBook 威胁情报适配器 —— 需免费注册 apikey。

国内标杆情报源，覆盖 C2 / 恶意软件 / 钓鱼 / 扫描 / 傀儡机等威胁类型，
提供地理位置、ASN、严重级别、置信度等上下文。

- IP 查询:   GET https://api.threatbook.cn/v3/scene/ip_reputation
             params: {apikey, resource: <ip>}
- 域名查询: GET https://api.threatbook.cn/v3/domain/query
             params: {apikey, resource: <domain>}
- 响应: data.<resource>.is_malicious (bool) → 命中判定
- Key: https://x.threatbook.cn 注册后获取；个人免费版 IP 信誉约 50 次/天
- 注意：免费额度有限，建议默认停用，用于人工核查/低频场景
"""

import logging

import httpx
from adapters.http_base import _IPV4_TRANSPORT

from adapters import ThreatIntelAdapter, ThreatResult

logger = logging.getLogger("platform.adapters.threatbook")

API_HOST = "https://api.threatbook.cn"


class ThreatBookAdapter(ThreatIntelAdapter):
    name = "threatbook"
    supports_domain = True
    supports_ip = True
    adapter_type = "http"
    is_builtin = True

    def __init__(self, base_url: str = "", api_key: str = "",
                 timeout_ms: int = 2000, config: str = ""):
        super().__init__(base_url=base_url or API_HOST, api_key=api_key,
                         timeout_ms=timeout_ms, config=config)
        self.api_key = self.config.get("api_key") or self.api_key

    def _get(self, path: str, resource: str) -> dict | None:
        if not self.api_key:
            logger.info("微步未配置 apikey，跳过查询 %s", resource)
            return None
        url = f"{self.base_url}{path}"
        try:
            resp = httpx.get(
                url,
                params={"apikey": self.api_key, "resource": resource},
                headers={"User-Agent": "dns-security-filter/1.0"},
                timeout=self.timeout_ms / 1000.0,
                follow_redirects=True,
                             transport=_IPV4_TRANSPORT)
        except Exception as e:
            logger.info("微步请求失败 %s: %s", resource, e)
            return None
        if resp.status_code != 200:
            logger.info("微步响应 %s: %s", resp.status_code, resp.text[:200])
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    @staticmethod
    def _parse(data: dict | None, resource: str) -> ThreatResult | None:
        if data is None:
            return None  # 网络失败 / 未配置 Key → 无结论
        entry = (data.get("data") or {}).get(resource)
        if not isinstance(entry, dict):
            # 配额超限 / 参数错误等 → 无结论
            logger.info("微步响应无 %s 数据: %s", resource,
                        str(data)[:200])
            return None
        is_mal = entry.get("is_malicious")
        if is_mal is None:
            # 判定字段缺失 → 无结论
            logger.info("微步响应缺少 is_malicious: %s", resource)
            return None
        if is_mal:
            severity = entry.get("severity") or "unknown"
            judgments = entry.get("judgments") or []
            detail = "微步判定恶意"
            if judgments:
                detail += "：" + "/".join(judgments[:3])
            elif severity != "unknown":
                detail += f"（severity={severity}）"
            return ThreatResult(True, "threatbook", detail)
        return ThreatResult(False, "threatbook", "未命中")

    def query_domain(self, domain: str) -> ThreatResult | None:
        return self._parse(self._get("/v3/domain/query", domain), domain)

    def query_ip(self, ip: str) -> ThreatResult | None:
        return self._parse(self._get("/v3/scene/ip_reputation", ip), ip)
