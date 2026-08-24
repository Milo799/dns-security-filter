"""测试中心：人工验证黑白名单规则与威胁情报源命中情况。

与真实检测链路共用同一批底层函数（detectors 的名单匹配 / adapters 的
情报源查询），但不写日志、不影响运行时状态。用于上线前验证规则、
排查"为什么某个域名被拦/没被拦"。

接口：
  POST /api/test/domain  {domain, query_type?, client_ip?}
  POST /api/test/ip      {ip}
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from adapters import get_enabled_adapters, run_fusion, ThreatResult
from app.auth import get_current_user
from app.db import get_enabled_list
from config import CONFIG
from detectors import _match_domain, _match_ip, query_upstream

router = APIRouter(prefix="/api/test", tags=["test"])

STATUS_LABEL = {
    "hit": "命中（恶意）",
    "miss": "未命中",
    "error": "无结论",
    "skip": "不支持",
}


class DomainTestBody(BaseModel):
    domain: str
    query_type: str = "A"      # A / AAAA
    client_ip: str = ""        # 可选，仅用于模拟日志场景（不做真实性校验）


class IpTestBody(BaseModel):
    ip: str


def _find_domain_rule(list_type: str, domain: str) -> str | None:
    for v in get_enabled_list(list_type, "domain"):
        if _match_domain(domain, [v]):
            return v
    return None


def _find_ip_rule(list_type: str, ip: str) -> str | None:
    for v in get_enabled_list(list_type, "ip"):
        if _match_ip(ip, [v]):
            return v
    return None


def _probe(kind: str, value: str) -> list[dict]:
    """逐源调用启用的情报源（按能力过滤），返回命中详情列表。

    status: hit(恶意) / miss(明确未命中) / error(无结论) / skip(不支持)
    """
    out: list[dict] = []
    for adapter in get_enabled_adapters():
        if kind == "domain" and not adapter.supports_domain:
            continue
        if kind == "ip" and not adapter.supports_ip:
            continue
        try:
            r = adapter.query_domain(value) if kind == "domain" \
                else adapter.query_ip(value)
        except Exception as e:  # 适配器自身异常也视为无结论
            out.append({"source": adapter.name, "status": "error",
                        "detail": f"异常：{e}"})
            continue
        if r is None:
            out.append({"source": adapter.name, "status": "error",
                        "detail": "无结论（超时/网络失败）"})
        elif r.is_malicious:
            out.append({"source": r.source, "status": "hit", "detail": r.detail})
        else:
            out.append({"source": r.source, "status": "miss",
                        "detail": r.detail or "未命中"})
    return out


def _fusion_verdict(probe: list[dict]) -> tuple[bool, str]:
    """对逐源结果做融合裁决；返回 (is_malicious, reason)。

    - 无任何支持源 → (False, "未启用支持该查询类型的情报源")
    - 全部无结论 → (True, "全部源无结论，按安全优先默认拦截")
    - 正常融合 → (bool, "any:1命中/2未命中" 摘要)
    """
    if not probe:
        return False, "未启用支持该查询类型的情报源"
    concluded = [r for r in probe if r["status"] in ("hit", "miss")]
    if not concluded:
        return True, "全部启用源均无结论，按安全优先默认拦截（fail-safe）"
    results = [ThreatResult(r["status"] == "hit", r["source"], r["detail"])
               for r in concluded]
    malicious = run_fusion(results, CONFIG.fusion_strategy)
    hits = sum(1 for r in concluded if r["status"] == "hit")
    reason = f"融合策略 {CONFIG.fusion_strategy}：{hits}/{len(concluded)} 个源判定恶意"
    return malicious, reason


@router.post("/domain")
def test_domain(body: DomainTestBody, _: str = Depends(get_current_user)):
    domain = body.domain.strip().lower().rstrip(".")
    if not domain:
        raise HTTPException(status_code=400, detail="domain 不能为空")
    qtype = body.query_type.upper()
    if qtype not in ("A", "AAAA"):
        raise HTTPException(status_code=400, detail="query_type 须为 A/AAAA")

    out = {
        "domain": domain,
        "query_type": qtype,
        "client_ip": body.client_ip,
        "detection_enabled": bool(CONFIG.detection_enabled),
        "whitelist": {"matched": False, "rule": None},
        "local_blacklist": {"matched": False, "rule": None},
        "threatintel_domain": [],
        "domain_verdict": None,
        "resolution": None,
        "ip_checks": [],
        "final_verdict": None,
    }

    # 1) 白名单（优先级最高）
    rule = _find_domain_rule("whitelist", domain)
    if rule:
        out["whitelist"] = {"matched": True, "rule": rule}
        out["domain_verdict"] = {"action": "allow",
                                 "reason": f"白名单命中：{rule}"}
        out["final_verdict"] = {"action": "allow", "reason": "直接放行"}
        return {"code": 0, "message": "ok", "data": out}

    # 2) 本地黑名单
    rule = _find_domain_rule("blacklist", domain)
    if rule:
        out["local_blacklist"] = {"matched": True, "rule": rule}
        out["domain_verdict"] = {"action": "intercept",
                                 "reason": f"本地黑名单命中：{rule}"}
        out["final_verdict"] = {"action": "intercept",
                                "reason": "返回告警应答（alert_ip）"}
        return {"code": 0, "message": "ok", "data": out}

    # 3) 威胁情报域名检测
    probe = _probe("domain", domain)
    out["threatintel_domain"] = probe
    bad, reason = _fusion_verdict(probe)
    if bad:
        out["domain_verdict"] = {"action": "intercept", "reason": reason}
        out["final_verdict"] = {"action": "intercept",
                                "reason": "返回告警应答（alert_ip）"}
        return {"code": 0, "message": "ok", "data": out}

    # 4) 公网解析 + IP 后置（测试模式：解析失败仅提示，不判 SERVFAIL）
    ips = query_upstream(domain, qtype)
    out["resolution"] = {"ok": bool(ips), "ips": ips}
    out["domain_verdict"] = {"action": "forward", "reason": reason or "无命中规则"}

    for ip in ips:
        ip_rule = _find_ip_rule("blacklist", ip)
        ip_probe = _probe("ip", ip)
        ip_bad, ip_reason = _fusion_verdict(ip_probe)
        out["ip_checks"].append({
            "ip": ip,
            "local_blacklist": {"matched": bool(ip_rule), "rule": ip_rule},
            "threatintel_ip": ip_probe,
            "verdict": "intercept" if (ip_rule or ip_bad) else "allow",
            "reason": ip_reason if (ip_rule or ip_bad) else "全部通过",
        })

    blocked = [c for c in out["ip_checks"] if c["verdict"] == "intercept"]
    if blocked:
        out["final_verdict"] = {
            "action": "intercept",
            "reason": f"IP 后置过滤：{len(blocked)}/{len(ips)} 个 IP 被判恶意",
        }
    else:
        out["final_verdict"] = {"action": "forward", "reason": "域名与全部 IP 均通过"}
    return {"code": 0, "message": "ok", "data": out}


@router.post("/ip")
def test_ip(body: IpTestBody, _: str = Depends(get_current_user)):
    ip = body.ip.strip()
    if not ip:
        raise HTTPException(status_code=400, detail="ip 不能为空")

    ip_rule = _find_ip_rule("blacklist", ip)
    probe = _probe("ip", ip)
    bad, reason = _fusion_verdict(probe)

    return {"code": 0, "message": "ok", "data": {
        "ip": ip,
        "local_blacklist": {"matched": bool(ip_rule), "rule": ip_rule},
        "threatintel_ip": probe,
        "verdict": "intercept" if (ip_rule or bad) else "allow",
        "reason": (f"本地黑名单命中：{ip_rule}" if ip_rule
                   else (reason if bad else "全部情报源未命中")),
    }}
