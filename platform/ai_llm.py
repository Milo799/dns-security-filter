"""LLM 智能中枢（迭代 49 · AI 能力规划 P3）。

定位（方案 §5 架构）：
  LLM 只做"翻译/归纳"——把 ai_findings 的结构化结论（算法层产出、
  带证据）转成自然语言。**LLM 不参与任何安全判定**，也不进解析主链路。

两个关键设计：
  1. **可降级**：未配置 API Key（或调用失败）时，自动返回"结构化报告"
     ——纯文本拼接各模块结论，不依赖外部服务。保证功能永远可用。
  2. **模型可切换**：OpenAI 兼容接口（base_url + model + api_key），
     可接任意 OpenAI 兼容服务（云端 API / 私有化），出站经 CONFIG.http_proxy。

配置（system_config 热生效）：
  llm_enabled   总开关（默认 0——未配置 key 时保持关闭）
  llm_base_url  OpenAI 兼容端点（如 https://api.example-llm.com/v1）
  llm_api_key   API Key（空 = 未配置，走结构化降级）
  llm_model     模型名（按服务商填写）
"""

import json
import logging
import time

from config import CONFIG
from app.db import db_cursor

logger = logging.getLogger("platform.ai_llm")

_TIMEOUT_S = 60
_MAX_FINDINGS_IN_PROMPT = 40


# ---------------------------------------------------------------------------
# 配置与可用性
# ---------------------------------------------------------------------------


def _cfg(key: str, default: str = "") -> str:
    return (getattr(CONFIG, key, default) or "").strip()


def is_llm_enabled() -> bool:
    """LLM 是否可用：总开关开 + base_url + api_key + model 齐备。"""
    return bool(getattr(CONFIG, "llm_enabled", False)
                and _cfg("llm_base_url") and _cfg("llm_api_key")
                and _cfg("llm_model"))


def _chat(messages: list[dict], temperature: float = 0.3) -> str:
    """调用 OpenAI 兼容 chat/completions（经 CONFIG.http_proxy 出站）。"""
    import requests
    url = _cfg("llm_base_url").rstrip("/") + "/chat/completions"
    headers = {"Authorization": "Bearer " + _cfg("llm_api_key"),
               "Content-Type": "application/json"}
    body = {"model": _cfg("llm_model"), "messages": messages,
            "temperature": temperature}
    proxy = _cfg("http_proxy")
    proxies = {"http": proxy, "https": proxy} if proxy else None
    r = requests.post(url, headers=headers, json=body, timeout=_TIMEOUT_S,
                      proxies=proxies)
    r.raise_for_status()
    data = r.json()
    return data["choices"][0]["message"]["content"].strip()


# ---------------------------------------------------------------------------
# 数据汇总（喂给 LLM 的"事实"，全部来自算法层证据）
# ---------------------------------------------------------------------------

_TYPE_LABEL = {
    "dga_suspect": "疑似 DGA 域名",
    "tunnel_suspect": "疑似 DNS 隧道",
    "false_positive": "疑似误报（建议加白）",
    "threat_cluster": "威胁族群",
    "client_anomaly": "异常客户端（疑似失陷）",
    "intel_quality": "情报源质量",
}


def collect_findings(limit_per_type: int = 8) -> dict:
    """按类型收集待确认结论（供报告与问答的事实来源）。"""
    out = {}
    with db_cursor() as cur:
        for t in _TYPE_LABEL:
            cur.execute(
                """SELECT target, score, evidence FROM ai_findings
                   WHERE type=? AND status='pending'
                   ORDER BY score DESC LIMIT ?""", (t, limit_per_type))
            rows = cur.fetchall()
            if not rows:
                continue
            items = []
            for r in rows:
                try:
                    ev = json.loads(r["evidence"]) if r["evidence"] else {}
                except (ValueError, TypeError):
                    ev = {}
                items.append({"target": r["target"],
                              "score": round(r["score"], 3), "evidence": ev})
            out[t] = items
    return out


def _stats_snapshot() -> dict:
    with db_cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM domain_first_seen")
        fs = cur.fetchone()["n"]
        cur.execute("SELECT COUNT(*) AS n FROM domain_first_seen "
                    "WHERE first_seen >= datetime('now','localtime','-24 hours')")
        fs24 = cur.fetchone()["n"]
        cur.execute("SELECT type, COUNT(*) AS n FROM ai_findings "
                    "WHERE status='pending' GROUP BY type")
        pend = {r["type"]: r["n"] for r in cur.fetchall()}
    return {"first_seen_total": fs, "first_seen_24h": fs24, "pending": pend}


def _structured_report() -> str:
    """无 LLM 时的结构化报告（降级路径，纯文本）。"""
    st = _stats_snapshot()
    findings = collect_findings()
    lines = ["【AI 安全洞察日报（结构化）】",
             f"数据地基：域名首现表累计 {st['first_seen_total']} 条，"
             f"近 24h 新增 {st['first_seen_24h']} 条。", ""]
    if not findings:
        lines.append("本轮未发现待确认的 AI 结论。")
        return "\n".join(lines)
    for t, items in findings.items():
        lines.append(f"■ {_TYPE_LABEL.get(t, t)}（{len(items)} 项待确认）")
        for it in items:
            lines.append(f"  · {it['target']}（评分 {it['score']}）")
        lines.append("")
    lines.append("提示：配置 LLM（llm_enabled + base_url + api_key + model）"
                 "可获得自然语言研判报告。")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 三大能力
# ---------------------------------------------------------------------------


def _prompt_daily_report(st: dict, findings: dict) -> list[dict]:
    return [
        {"role": "system", "content":
         "你是企业 DNS 安全分析师。根据给定的结构化检测结论，写一份"
         "简洁的中文安全日报。要求：先总述风险态势，再按威胁类型分点"
         "说明（每点给出对象、评分与关键证据含义），最后给出处置建议"
         "（哪些建议加白、哪些需进一步核查）。只依据给定数据，不要编造。"
         "控制在 500 字以内。"},
        {"role": "user", "content": json.dumps(
            {"统计数据": st, "AI 结论": findings}, ensure_ascii=False)},
    ]


def generate_daily_report(use_llm: bool = True) -> dict:
    """生成每日研判报告。返回 {source, content}（source: llm/structured）。"""
    st = _stats_snapshot()
    findings = collect_findings()
    if not findings and st["first_seen_24h"] == 0:
        return {"source": "structured",
                "content": "【AI 安全洞察日报】\n本轮无待确认结论，数据采集中。"}
    if use_llm and is_llm_enabled():
        try:
            text = _chat(_prompt_daily_report(st, findings))
            return {"source": "llm", "content": text}
        except Exception as e:
            logger.warning("LLM 日报生成失败，降级结构化：%s", e)
    return {"source": "structured", "content": _structured_report()}


def summarize_domain(domain: str, use_llm: bool = True) -> dict:
    """域名研判摘要：汇总该域名的全部 AI 证据 → 一段话结论。"""
    d = (domain or "").strip().lower().rstrip(".")
    if not d:
        return {"source": "structured", "content": "域名无效。"}
    with db_cursor() as cur:
        cur.execute(
            """SELECT type, score, evidence, status FROM ai_findings
               WHERE target=? OR target LIKE ? ORDER BY score DESC LIMIT 20""",
            (d, "%|" + d))
        rows = cur.fetchall()
        cur.execute("SELECT filter_reason, action, COUNT(*) AS n FROM filter_log "
                    "WHERE domain=? GROUP BY filter_reason, action "
                    "ORDER BY n DESC LIMIT 10", (d,))
        logs = cur.fetchall()
        cur.execute("SELECT registered_at FROM nrd_cache WHERE domain=?", (d,))
        nrd = cur.fetchone()
        cur.execute("SELECT first_seen FROM domain_first_seen WHERE domain=?",
                    (d,))
        fs = cur.fetchone()

    facts = {
        "domain": d,
        "first_seen": fs["first_seen"] if fs else None,
        "registered_at": nrd["registered_at"] if nrd else None,
        "filter_history": [{"reason": r["filter_reason"], "action": r["action"],
                            "count": r["n"]} for r in logs],
        "ai_findings": [],
    }
    for r in rows:
        try:
            ev = json.loads(r["evidence"]) if r["evidence"] else {}
        except (ValueError, TypeError):
            ev = {}
        facts["ai_findings"].append(
            {"type": r["type"], "score": round(r["score"], 3), "evidence": ev})

    # 结构化摘要（降级路径同时作为 LLM 输入）
    parts = [f"域名 {d}："]
    if facts["first_seen"]:
        parts.append(f"首次出现于 {facts['first_seen']}。")
    if facts["registered_at"]:
        parts.append(f"注册时间 {facts['registered_at']}。")
    if facts["ai_findings"]:
        for f in facts["ai_findings"]:
            parts.append(f"AI 判定[{f['type']}] 评分 {f['score']}。")
    else:
        parts.append("暂无 AI 判定结论。")
    if facts["filter_history"]:
        h = facts["filter_history"][0]
        parts.append(f"历史拦截 {h['count']} 次（{h['reason']}）。")
    structured = "".join(parts)

    if use_llm and is_llm_enabled():
        try:
            text = _chat([
                {"role": "system", "content":
                 "你是 DNS 安全分析师。根据给定的域名事实，用 2~3 句话给出"
                 "研判结论（是否可疑、依据是什么、建议如何处理）。只依据"
                 "事实，不要编造。"},
                {"role": "user", "content": json.dumps(facts, ensure_ascii=False)},
            ])
            return {"source": "llm", "content": text, "facts": facts}
        except Exception as e:
            logger.warning("LLM 域名摘要失败，降级结构化：%s", e)
    return {"source": "structured", "content": structured, "facts": facts}


def ask(question: str, use_llm: bool = True) -> dict:
    """自然语言问答：以当前 AI 结论为事实上下文回答问题。"""
    q = (question or "").strip()
    if not q:
        return {"source": "structured", "content": "请提供问题。"}
    st = _stats_snapshot()
    findings = collect_findings(limit_per_type=12)
    if not (use_llm and is_llm_enabled()):
        return {"source": "structured",
                "content": "（未配置 LLM，以下为当前 AI 结论概览）\n"
                           + _structured_report()}
    try:
        text = _chat([
            {"role": "system", "content":
             "你是企业 DNS 安全分析助手。仅依据给定的结构化结论回答用户"
             "问题；数据中没有的信息要明确说明「数据中未包含」，不要"
             "编造。"},
            {"role": "user", "content":
             f"当前 AI 结论：{json.dumps({'统计数据': st, 'AI 结论': findings}, ensure_ascii=False)}\n\n"
             f"用户问题：{q}"},
        ], temperature=0.2)
        return {"source": "llm", "content": text}
    except Exception as e:
        logger.warning("LLM 问答失败，降级结构化：%s", e)
        return {"source": "structured",
                "content": "LLM 调用失败，以下为当前结论概览：\n"
                           + _structured_report()}
