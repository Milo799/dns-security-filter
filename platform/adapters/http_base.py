"""HTTP 威胁情报适配器基类：统一的 GET 请求 + 超时 + 异常转 None。

子类只需实现 _parse_domain_response / _parse_ip_response，
专注各厂商响应结构的解析，网络与错误处理全部在这里统一。

网络出口统一走 app.http_client（共享 Client）：
IPv4 强制 + 可选代理（CONFIG.http_proxy，Web 界面热配置）。
"""

import logging

from app import http_client

from adapters import ThreatIntelAdapter

logger = logging.getLogger("platform.adapters.http")


class HttpThreatIntelAdapter(ThreatIntelAdapter):
    """基于 HTTP GET + JSON 响应的适配器基类。"""

    def _get(self, path_or_url: str, *, headers: dict | None = None,
             params: dict | None = None) -> dict | None:
        """发 GET 请求返回 JSON；任何失败（超时/非200/解析失败）返回 None。"""
        url = path_or_url if path_or_url.startswith("http") \
            else f"{self.base_url}{path_or_url}"
        if not url:
            return None
        try:
            resp = http_client.get(url, headers=headers, params=params,
                                   timeout=self.timeout_ms / 1000.0)
        except Exception as e:
            logger.info("情报源 %s 请求失败 %s: %s", self.name, url, e)
            return None
        if resp.status_code != 200:
            logger.info("情报源 %s 响应 %s: %s", self.name,
                        resp.status_code, resp.text[:200])
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    # ---- 子类按能力覆写 ----

    def query_domain(self, domain: str):
        data = self._get(self._domain_path(domain), headers=self._auth_headers(),
                         params=self._domain_params(domain))
        if data is None:
            return None
        return self._parse_domain_response(domain, data)

    def query_ip(self, ip: str):
        data = self._get(self._ip_path(ip), headers=self._auth_headers(),
                         params=self._ip_params(ip))
        if data is None:
            return None
        return self._parse_ip_response(ip, data)

    # ---- 子类需提供的钩子 ----

    def _auth_headers(self) -> dict:
        """鉴权头（如 x-apikey / Key）。默认无。"""
        return {}

    def _domain_path(self, domain: str) -> str:
        return f"/{domain}"

    def _domain_params(self, domain: str) -> dict | None:
        return None

    def _ip_path(self, ip: str) -> str:
        return f"/{ip}"

    def _ip_params(self, ip: str) -> dict | None:
        return None

    def _parse_domain_response(self, domain: str, data: dict):
        raise NotImplementedError

    def _parse_ip_response(self, ip: str, data: dict):
        raise NotImplementedError
