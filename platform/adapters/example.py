"""示例威胁情报适配器（占位实现）。

AI 开发指引：
  1. 复制本文件为 <厂商名>.py（HTTP 类源可继承 adapters.http_base.
     HttpThreatIntelAdapter，只需实现响应解析钩子）；
  2. 将配置写入 threatintel_api 表（Web 界面「威胁情报源」）；
  3. 在 adapters/__init__.py 的 _build_registry() 注册 name → 类。

统一约束：异常/超时必须返回 None，不抛异常；超时用 timeout_ms。
"""

import logging

from adapters import ThreatIntelAdapter, ThreatResult

logger = logging.getLogger("platform.adapters")


class ExampleAdapter(ThreatIntelAdapter):
    """占位示例：不做真实请求，恒返回 None（无结论），仅演示接口形态。"""

    name = "example"
    supports_domain = True
    supports_ip = True

    def query_domain(self, domain: str) -> ThreatResult | None:
        logger.debug("example adapter query_domain: %s", domain)
        return None

    def query_ip(self, ip: str) -> ThreatResult | None:
        logger.debug("example adapter query_ip: %s", ip)
        return None
