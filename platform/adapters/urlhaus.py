"""URLhaus（abuse.ch）恶意 URL 分发库适配器 —— 开放 API，需 Auth-Key。

- 域名/IP 查询: POST https://urlhaus-api.abuse.ch/v1/host/  {host: <域名或IP>}
  （官方无独立 /v1/ip/ 端点，host 参数直接接受 IPv4/IPv6 地址）
- 认证：所有请求必须携带 HTTP 头 `Auth-Key`（在 https://auth.abuse.ch/
  免费申请）。未配置或 key 无效时服务端返回 401 Unauthorized。
- 响应 query_status: "ok"(命中) / "no_results"(未命中) /
  "invalid_*"/"http_get_expected"/"http_post_expected"(请求问题 → 无结论 None)
- URL 级语义：URLhaus 收录的是恶意 URL（含域名路径），非整个域名；
  本适配器只把"当前在线(url_status=online)"的恶意 URL 判为命中，
  全部 offline/unknown 视为历史记录 → 明确未命中（避免死链误报）。
- 官方要求限速：查询间隔至少 5 秒（建议更长），因此默认停用，
  由管理员在需要时手动开启（仅用于人工核查场景）。
- 适配器维护 last_error：最近一次失败的具体原因（未配置 Key / Key 无效 /
  限速 / 网络错误等），供"测试连通性"接口直接展示。
"""

import logging

import httpx
from adapters.http_base import _IPV4_TRANSPORT

from adapters import ThreatIntelAdapter, ThreatResult

logger = logging.getLogger("platform.adapters.urlhaus")

API_HOST = "https://urlhaus-api.abuse.ch"
ERR_NO_KEY = ("该源需要 Auth-Key：请到 https://auth.abuse.ch/ 免费申请后，"
              "在本源编辑页的 API Key 中填写")


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
        self.last_error = ""

    def _post(self, path: str, data: dict) -> dict | None:
        url = f"{self.base_url}{path}"
        headers = {"User-Agent": "dns-security-filter/1.0"}
        if self.api_key:
            headers["Auth-Key"] = self.api_key
        try:
            resp = httpx.post(url, data=data, headers=headers,
                              timeout=self.timeout_ms / 1000.0,
                              follow_redirects=True,
                             transport=_IPV4_TRANSPORT)
        except Exception as e:
            self.last_error = f"网络/超时错误：{e}"
            logger.info("URLhaus 请求失败 %s: %s", url, e)
            return None
        if resp.status_code in (401, 403):
            self.last_error = (ERR_NO_KEY if not self.api_key
                               else "Auth-Key 无效或已被撤销，请检查 API Key")
            logger.info("URLhaus 鉴权失败 %s: %s",
                        resp.status_code, resp.text[:200])
            return None
        if resp.status_code == 429:
            self.last_error = "请求过于频繁（rate limit），请稍后重试"
            logger.info("URLhaus 限速 %s", resp.status_code)
            return None
        if resp.status_code != 200:
            self.last_error = f"HTTP {resp.status_code}"
            logger.info("URLhaus 响应 %s: %s",
                        resp.status_code, resp.text[:200])
            return None
        try:
            return resp.json()
        except ValueError:
            self.last_error = "响应不是合法 JSON"
            return None

    def _parse(self, data: dict | None) -> ThreatResult | None:
        if data is None:
            return None  # 网络/鉴权失败无结论（last_error 已记录）
        status = data.get("query_status")
        if status == "ok":
            urls = data.get("urls", []) or []
            online = [u for u in urls
                      if str(u.get("url_status", "")).lower() == "online"]
            if online:
                self.last_error = ""
                return ThreatResult(
                    True, "urlhaus",
                    f"URLhaus 收录 {len(online)} 条当前在线恶意 URL")
            # 全部 offline/unknown → 仅历史记录，不构成当前威胁。
            # 与 URLhaus hostfile（只列在线 URL）口径一致，避免 2021 年
            # 死链等历史记录把正常域名（如 baidu.com）误判为恶意。
            self.last_error = ""
            if urls:
                return ThreatResult(
                    False, "urlhaus",
                    f"仅 {len(urls)} 条历史记录（已离线/未知），当前未命中")
            return ThreatResult(False, "urlhaus", "未命中")
        if status == "no_results":
            self.last_error = ""
            return ThreatResult(False, "urlhaus", "未命中")
        # invalid_host / http_get_expected / http_post_expected 等 → 请求未成功
        self.last_error = f"URLhaus 返回异常状态: {status}"
        return None

    def _query(self, data: dict) -> ThreatResult | None:
        if not self.api_key:
            self.last_error = ERR_NO_KEY
            return None
        return self._parse(self._post("/v1/host/", data))

    def query_domain(self, domain: str) -> ThreatResult | None:
        return self._query({"host": domain})

    def query_ip(self, ip: str) -> ThreatResult | None:
        # 官方 API 无 /v1/ip/ 端点；host 参数直接接受 IP 地址
        return self._query({"host": ip})
