"""威胁情报适配器框架（对应 PRD 5.3）。

每个情报源实现一个适配器，注册后通过 Web 界面启用/禁用。
新增情报源只需新增适配器文件 + 配置入库，不改动检测主流程。
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
      - name: 情报源名称（唯一，如 "virustotal"）
      - query_domain(domain) -> ThreatResult | None
      - query_ip(ip) -> ThreatResult | None     # ip 可为 IPv4 或 IPv6

    调用异常或超时必须返回 None，表示该源本次无结论（不参与融合统计）。
    具体请求构造、鉴权、响应解析在子类中完成。
    """

    name: str = ""

    @abstractmethod
    def query_domain(self, domain: str) -> ThreatResult | None:
        """查询域名，返回统一结果；异常/超时返回 None。"""
        raise NotImplementedError

    @abstractmethod
    def query_ip(self, ip: str) -> ThreatResult | None:
        """查询 IP（IPv4/IPv6），返回统一结果；异常/超时返回 None。"""
        raise NotImplementedError


def get_enabled_adapters() -> list[ThreatIntelAdapter]:
    """返回当前启用的适配器实例列表。

    从 threatintel_api 表读取 enabled=1 的配置，按 ADAPTER_REGISTRY
    实例化适配器（配置含 base_url、api_key、timeout_ms）。

    AI 开发指引：新增情报源时——
      1. 新建适配器文件（继承 ThreatIntelAdapter）；
      2. 在 ADAPTER_REGISTRY 注册 name → 类；
      3. Web 界面「威胁情报源」新增配置并启用。
    """
    from adapters.example import ExampleAdapter  # 局部导入避免循环依赖

    registry = {"example": ExampleAdapter}  # TODO(AI): 注册真实情报源适配器

    adapters: list[ThreatIntelAdapter] = []
    with db_cursor() as cur:
        cur.execute("SELECT * FROM threatintel_api WHERE enabled=1")
        for row in cur.fetchall():
            cls = registry.get(row["name"])
            if cls is None:
                continue
            try:
                adapters.append(cls(
                    base_url=row["base_url"],
                    api_key=row["api_key"],
                    timeout_ms=row["timeout_ms"],
                ))
            except TypeError as e:
                logger.warning("适配器 %s 实例化失败: %s", row["name"], e)
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
