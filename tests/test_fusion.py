"""威胁情报多源融合策略测试（adapters.run_fusion）。

覆盖 PRD 5.3：any / majority / all 三种策略判定。
"""

from adapters import ThreatResult, run_fusion


def make(name: str, malicious: bool) -> ThreatResult:
    return ThreatResult(is_malicious=malicious, source=name, confidence=1.0)


def test_any_strategy():
    assert run_fusion([make("a", False), make("b", True)], "any") is True
    assert run_fusion([make("a", False), make("b", False)], "any") is False


def test_all_strategy():
    assert run_fusion([make("a", True), make("b", True)], "all") is True
    assert run_fusion([make("a", True), make("b", False)], "all") is False


def test_majority_strategy():
    # 3 个源中 2 个恶意 → 恶意；2 个源中 1 个恶意 → 不判恶意（须超半数）
    assert run_fusion([make("a", True), make("b", True), make("c", False)], "majority") is True
    assert run_fusion([make("a", True), make("b", False)], "majority") is False


def test_empty_results_default_not_malicious():
    # 无任何结论：run_fusion 返回 False，由调用方（PRD）决定默认拦截
    assert run_fusion([], "any") is False
