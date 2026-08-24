"""VirusTotal 适配器（API v3）。

域名：GET {base}/domains/{domain}   头 x-apikey
IP：  GET {base}/ip_addresses/{ip}  头 x-apikey

判定：last_analysis_stats 中 malicious + suspicious > 0 即恶意。
文档：https://docs.virustotal.com/reference/overview
"""

from adapters import ThreatResult
from adapters.http_base import HttpThreatIntelAdapter


class VirusTotalAdapter(HttpThreatIntelAdapter):
    name = "virustotal"
    supports_domain = True
    supports_ip = True

    def __init__(self, base_url: str = "", api_key: str = "",
                 timeout_ms: int = 2000):
        if not base_url:
            base_url = "https://www.virustotal.com/api/v3"
        super().__init__(base_url, api_key, timeout_ms)

    def _auth_headers(self) -> dict:
        return {"x-apikey": self.api_key}

    def _domain_path(self, domain: str) -> str:
        return f"/domains/{domain}"

    def _ip_path(self, ip: str) -> str:
        return f"/ip_addresses/{ip}"

    @staticmethod
    def _stats_to_result(source: str, stats: dict, subject: str) -> ThreatResult:
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values() if isinstance(v, int))
        hits = malicious + suspicious
        return ThreatResult(
            is_malicious=hits > 0,
            source=source,
            detail=f"{subject}: malicious={malicious}, suspicious={suspicious}, "
                   f"harmless={stats.get('harmless', 0)}",
            confidence=hits / total if total else 0.0,
        )

    def _parse_domain_response(self, domain: str, data: dict) -> ThreatResult:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return self._stats_to_result(self.name, stats, domain)

    def _parse_ip_response(self, ip: str, data: dict) -> ThreatResult:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return self._stats_to_result(self.name, stats, ip)
