"""示例威胁情报适配器（占位实现）。

AI 开发指引：
  1. 复制本文件为 <厂商名>.py，按厂商 API 文档实现 query_domain / query_ip；
  2. 将配置写入 threatintel_api 表（Web 界面「威胁情报源」或直接入库）；
  3. 在 get_enabled_adapters() 中完成配置 → 实例的映射。

统一约束：异常/超时必须返回 None，不抛异常；超时用 CONFIG.api_timeout_ms。
"""

import logging

from adapters import ThreatIntelAdapter, ThreatResult

logger = logging.getLogger("platform.adapters")


class ExampleAdapter(ThreatIntelAdapter):
    """占位示例：不做真实请求，恒返回 None（无结论），仅演示接口形态。"""

    name = "example"

    def __init__(self, base_url: str = "", api_key: str = "",
                 timeout_ms: int = 2000):
        self.base_url = base_url
        self.api_key = api_key
        self.timeout_ms = timeout_ms

    def query_domain(self, domain: str) -> ThreatResult | None:
        # TODO(AI): 实现真实请求，如：
        #   resp = requests.get(f"{self.base_url}/domain/{domain}",
        #                       headers={"Authorization": f"Bearer {self.api_key}"},
        #                       timeout=self.timeout_ms / 1000)
        #   return ThreatResult(is_malicious=..., source=self.name, detail=..., confidence=...)
        logger.debug("example adapter query_domain: %s", domain)
        return None

    def query_ip(self, ip: str) -> ThreatResult | None:
        # TODO(AI): 实现真实请求（同上形态）
        logger.debug("example adapter query_ip: %s", ip)
        return None
