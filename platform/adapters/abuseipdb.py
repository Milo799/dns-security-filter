"""AbuseIPDB 适配器（API v2）。

IP：GET {base}/check?ipAddress={ip}&maxAgeInDays=90  头 Key（API Key）
域名：不支持（supports_domain=False，不参与域名前置检测）。

判定：abuseConfidenceScore >= 25 即恶意（阈值可按运营经验调整）。
文档：https://docs.abuseipdb.com/
"""

from adapters import ThreatResult
from adapters.http_base import HttpThreatIntelAdapter

CONFIDENCE_THRESHOLD = 25


class AbuseIPDBAdapter(HttpThreatIntelAdapter):
    name = "abuseipdb"
    supports_domain = False   # 仅支持 IP 查询
    supports_ip = True

    def __init__(self, base_url: str = "", api_key: str = "",
                 timeout_ms: int = 2000):
        if not base_url:
            base_url = "https://api.abuseipdb.com/api/v2"
        super().__init__(base_url, api_key, timeout_ms)

    def _auth_headers(self) -> dict:
        return {"Key": self.api_key, "Accept": "application/json"}

    def _ip_path(self, ip: str) -> str:
        return "/check"

    def _ip_params(self, ip: str) -> dict:
        return {"ipAddress": ip, "maxAgeInDays": 90}

    def _parse_ip_response(self, ip: str, data: dict) -> ThreatResult:
        attrs = data["data"]
        score = int(attrs.get("abuseConfidenceScore", 0))
        return ThreatResult(
            is_malicious=score >= CONFIDENCE_THRESHOLD,
            source=self.name,
            detail=f"{ip}: confidence={score}%, "
                   f"total_reports={attrs.get('totalReports', 0)}",
            confidence=score / 100.0,
        )

    def _parse_domain_response(self, domain: str, data: dict):
        return None  # 不会被调用（supports_domain=False）
