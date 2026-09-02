"""GreyNoise Community API 适配器 —— 需免费社区 API Key。

GreyNoise 的定位是"互联网背景噪声（扫描器/蠕虫/探测）识别"：它告诉你是
否有扫描器在持续扫描某个 IP、该噪声是恶意还是良性。专治"误拦扫描 IP"——
社区 API 里只有 classification=malicious 才判恶意拦截；benign（扫描但无害）、
unknown、riot（已知良性基础设施）一律不拦，避免把正常扫描流量当成攻击。

- 查询: GET https://api.greynoise.io/v3/community/{ip}
  Header: key: <api_key>
- 响应 classification:
  * "malicious" → 命中（互联网扫描且带恶意行为）
  * "benign" / "unknown" / riot → 明确未命中（不拦，宁可放行）
  * HTTP 404（IP 不在 GreyNoise 数据集）→ 明确未命中
  * 401（Key 无效/超配额）或其它非 200 / 网络异常 → 无结论 None
- 能力：仅支持 IP（社区 API 不支持域名查询）
- Key: https://docs.greynoise.io/reference/community-ip-lookup 免费注册
"""

import logging

import httpx
from app import http_client

from adapters import ThreatIntelAdapter, ThreatResult

logger = logging.getLogger("platform.adapters.greynoise")

API_HOST = "https://api.greynoise.io"


class GreyNoiseAdapter(ThreatIntelAdapter):
    name = "greynoise"
    supports_domain = False
    supports_ip = True
    adapter_type = "http"
    is_builtin = True

    def __init__(self, base_url: str = "", api_key: str = "",
                 timeout_ms: int = 2000, config: str = ""):
        super().__init__(base_url=base_url or API_HOST, api_key=api_key,
                         timeout_ms=timeout_ms, config=config)
        self.api_key = self.config.get("api_key") or self.api_key

    def _search(self, ip: str) -> tuple[int | None, dict | None]:
        if not self.api_key:
            logger.info("GreyNoise 未配置 API Key，跳过查询 %s", ip)
            return None, None
        url = f"{self.base_url}/v3/community/{ip}"
        try:
            resp = http_client.get(
                url,
                headers={"key": self.api_key,
                         "User-Agent": "dns-security-filter/1.0"},
                timeout=self.timeout_ms / 1000.0)
        except Exception as e:
            logger.info("GreyNoise 请求失败 %s: %s", ip, e)
            return None, None
        if resp.status_code == 404:
            return 404, None  # 不在数据集 → 明确未命中
        if resp.status_code != 200:
            logger.info("GreyNoise 响应 %s: %s", resp.status_code,
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
            return ThreatResult(False, "greynoise", "GreyNoise 无此 IP 记录")
        if status != 200 or data is None:
            return None  # 鉴权失败 / 超配额 / 网络失败 → 无结论
        classification = data.get("classification") or "unknown"
        if classification == "malicious":
            name = data.get("name") or "互联网扫描"
            detail = f"GreyNoise 恶意扫描：{name}"
            if data.get("noise"):
                detail += "（背景噪声）"
            return ThreatResult(True, "greynoise", detail)
        # benign / unknown / riot → 明确不拦（扫描器识别，避免误拦）
        return ThreatResult(False, "greynoise",
                            f"GreyNoise {classification}，不拦截")

    def query_domain(self, domain: str) -> ThreatResult | None:
        # 社区 API 仅支持 IP，能力声明 supports_domain=False，
        # 检测主流程不会调用；此处兜底返回无结论。
        return None

    def query_ip(self, ip: str) -> ThreatResult | None:
        return self._parse(*self._search(ip))
