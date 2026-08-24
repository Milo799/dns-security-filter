"""IBM X-Force Exchange 威胁情报适配器 —— 免费非商业 API（需注册生成 Key）。

IBM X-Force Exchange 云情报共享平台，覆盖恶意软件家族、C2、钓鱼、
扫描源等，响应含 0-10 风险评分（score）。

- 认证: HTTP Basic（api_key 作用户名，api_password 作密码）
- IP 查询:   GET https://api.xforce.ibmcloud.com/ipr/{ip}
             响应含 score(0-10)、verdicts、malware 家族、reason
- 域名查询: GET https://api.xforce.ibmcloud.com/url/{domain}
             响应含 score(0-10)
- 判定: score >= score_threshold（默认 5，config 可调）→ 命中
- Key: exchange.xforce.ibmcloud.com 登录后 Settings → API Access 生成
  （API Key + API Password 各一份；免费非商业额度有限）
- 注意：商业订阅需联系 IBM；个人/非商业免费版可用
"""

import logging

import httpx

from adapters import ThreatIntelAdapter, ThreatResult

logger = logging.getLogger("platform.adapters.xforce")

API_HOST = "https://api.xforce.ibmcloud.com"
DEFAULT_THRESHOLD = 5


class XForceAdapter(ThreatIntelAdapter):
    name = "xforce"
    supports_domain = True
    supports_ip = True
    adapter_type = "http"
    is_builtin = True

    def __init__(self, base_url: str = "", api_key: str = "",
                 timeout_ms: int = 2000, config: str = ""):
        super().__init__(base_url=base_url or API_HOST, api_key=api_key,
                         timeout_ms=timeout_ms, config=config)
        self.api_key = self.config.get("api_key") or self.api_key
        self.api_password = self.config.get("api_password") or ""
        try:
            self.threshold = int(self.config.get("score_threshold",
                                                 DEFAULT_THRESHOLD))
        except (TypeError, ValueError):
            self.threshold = DEFAULT_THRESHOLD

    def _get(self, path: str) -> dict | None:
        if not self.api_key or not self.api_password:
            logger.info("X-Force 未配置 api_key/api_password，跳过 %s", path)
            return None
        url = f"{self.base_url}{path}"
        try:
            resp = httpx.get(
                url,
                auth=(self.api_key, self.api_password),
                headers={"User-Agent": "dns-security-filter/1.0",
                         "Accept": "application/json"},
                timeout=self.timeout_ms / 1000.0,
                follow_redirects=True,
            )
        except Exception as e:
            logger.info("X-Force 请求失败 %s: %s", path, e)
            return None
        if resp.status_code != 200:
            # 401/402（配额超限）/404/5xx → 无结论
            logger.info("X-Force 响应 %s: %s", resp.status_code,
                        resp.text[:200])
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    @staticmethod
    def _parse(data: dict | None, threshold: int,
               kind: str) -> ThreatResult | None:
        if data is None:
            return None  # 网络失败 / 未配置 Key → 无结论
        score = data.get("score")
        if not isinstance(score, (int, float)):
            # 无 score 字段（如解析失败）→ 无结论
            logger.info("X-Force %s 响应无 score: %s", kind, str(data)[:200])
            return None
        if score >= threshold:
            reason = data.get("reason") or ""
            family = data.get("malware") or ""
            detail = f"X-Force 评分 {score}/10（阈值 {threshold}）"
            if reason:
                detail += f"：{str(reason)[:80]}"
            elif family:
                detail += f"：{str(family)[:60]}"
            return ThreatResult(True, "xforce", detail)
        return ThreatResult(False, "xforce",
                            f"评分 {score}/10，低于阈值 {threshold}")

    def query_domain(self, domain: str) -> ThreatResult | None:
        return self._parse(self._get(f"/url/{domain}"), self.threshold,
                           "domain")

    def query_ip(self, ip: str) -> ThreatResult | None:
        return self._parse(self._get(f"/ipr/{ip}"), self.threshold, "ip")
