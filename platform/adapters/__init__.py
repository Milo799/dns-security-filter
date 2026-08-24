"""威胁情报适配器框架（对应 PRD 5.3）。

每个情报源实现一个适配器，注册后通过 Web 界面启用/禁用。
新增情报源只需新增适配器文件 + 在 ADAPTER_REGISTRY 注册，不改动检测主流程。

能力声明（supports_domain / supports_ip）：
  某些源只支持 IP 查询（如 AbuseIPDB）或只支持域名查询。
  检测主流程只调用声明了该能力的启用源；若没有任何源支持当前
  查询类型，则跳过威胁情报检测（区别于"源超时无结论"——后者按
  PRD 5.3 默认拦截）。
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
import logging

from app.db import db_cursor

logger = logging.getLogger("platform.adapters")


@dataclass
class ThreatResult:
    """统一返回结构：is_malicious / source / detail / confidence"""
    is_malicious: bool
    source: str
    detail: str = ""
    confidence: float = 0.0   # 0~1，多数融合策略时使用


class ThreatIntelAdapter(ABC):
    """适配器统一接口。

    子类需实现：
      - name: 情报源名称（唯一，如 "virustotal"，与 threatintel_api.name 对应）
      - query_domain(domain) -> ThreatResult | None
      - query_ip(ip) -> ThreatResult | None     # ip 可为 IPv4 或 IPv6
      - supports_domain / supports_ip: 能力声明（默认均支持）

    调用异常或超时必须返回 None，表示该源本次无结论（不参与融合统计）。
    "该源不支持此类查询"由能力声明表达，不应通过返回 None 表达。
    """

    name: str = ""
    supports_domain: bool = True
    supports_ip: bool = True

    def __init__(self, base_url: str = "", api_key: str = "",
                 timeout_ms: int = 2000):
        self.base_url = base_url.rstrip("/") if base_url else ""
        self.api_key = api_key or ""
        self.timeout_ms = timeout_ms

    @abstractmethod
    def query_domain(self, domain: str) -> ThreatResult | None:
        """查询域名，返回统一结果；异常/超时返回 None。"""
        raise NotImplementedError

    @abstractmethod
    def query_ip(self, ip: str) -> ThreatResult | None:
        """查询 IP（IPv4/IPv6），返回统一结果；异常/超时返回 None。"""
        raise NotImplementedError


def get_adapter_cls(name: str) -> type[ThreatIntelAdapter] | None:
    """按名称取适配器类（供路由层连通性测试等场景使用）。"""
    return ADAPTER_REGISTRY.get(name)


def build_adapter(name: str, base_url: str, api_key: str = "",
                  timeout_ms: int = 2000) -> ThreatIntelAdapter | None:
    """按配置实例化适配器；未注册的名称返回 None。"""
    cls = ADAPTER_REGISTRY.get(name)
    if cls is None:
        return None
    return cls(base_url=base_url, api_key=api_key, timeout_ms=timeout_ms)


def get_enabled_adapters() -> list[ThreatIntelAdapter]:
    """返回当前启用的适配器实例列表。

    从 threatintel_api 表读取 enabled=1 的配置，按 ADAPTER_REGISTRY 实例化。
    """
    adapters: list[ThreatIntelAdapter] = []
    with db_cursor() as cur:
        cur.execute("SELECT * FROM threatintel_api WHERE enabled=1")
        for row in cur.fetchall():
            adapter = build_adapter(row["name"], row["base_url"],
                                    row["api_key"], row["timeout_ms"])
            if adapter is None:
                logger.warning("情报源 %s 未注册适配器，跳过", row["name"])
                continue
            adapters.append(adapter)
    return adapters


def run_fusion(results: list[ThreatResult], strategy: str) -> bool:
    """按融合策略判定最终是否恶意（PRD 5.3 多源融合）。

    - any（默认）: 任一源 is_malicious 即判恶意
    - majority: 有结论的源中，超半数判恶意才判恶意
    - all: 全部有结论的源均判恶意才判恶意
    - 无任何结论（列表为空）时由调用方决定（PRD：默认拦截）
    """
    if not results:
        return False
    if strategy == "all":
        return all(r.is_malicious for r in results)
    if strategy == "majority":
        malicious = sum(1 for r in results if r.is_malicious)
        return malicious > len(results) / 2
    # any（默认）
    return any(r.is_malicious for r in results)


def _build_registry() -> dict[str, type[ThreatIntelAdapter]]:
    """汇总所有适配器（局部导入避免循环依赖）。"""
    from adapters.example import ExampleAdapter
    from adapters.virustotal import VirusTotalAdapter
    from adapters.abuseipdb import AbuseIPDBAdapter
    return {
        "example": ExampleAdapter,
        "virustotal": VirusTotalAdapter,
        "abuseipdb": AbuseIPDBAdapter,
    }


ADAPTER_REGISTRY = _build_registry()
