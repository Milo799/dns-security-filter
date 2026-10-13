"""AI 旁路批处理器（迭代 49 · AI 能力规划 P0-4）。

职责：定时（默认 30 分钟）在低峰读库跑分析，把结论写入 ai_findings。
**只读源数据 + 只写结论表**，绝不触碰检测链路。

本轮实现两个分析（P0 范围）：
  1. **DGA 检测**：扫 domain_first_seen 最近窗口的新域名 → ai_analysis.dga_score
     → 超阈值写 ai_findings(type=dga_suspect)；
  2. **隧道检测**：把首现域名按（首现客户端, 可注册父域）聚合——
     DNS 隧道的子域几乎全是"新子域"，天然落在首现表里；
     子域数达门槛才评分（降噪）→ 超阈值写 ai_findings(type=tunnel_suspect)。

幂等：同 (type, target) 已有 pending 结论时**更新**评分与证据，
不重复插入（每轮重跑不产生重复行）。

配置（system_config 热生效）：
  ai_analysis_enabled            分析开关（默认 1）
  ai_analysis_interval_minutes   运行间隔分钟（默认 30，最小 5）
"""

import json
import logging
import threading
import time
from collections import defaultdict

from config import CONFIG
from app.db import db_cursor

import ai_analysis

logger = logging.getLogger("platform.ai_batch")

_DEFAULT_WINDOW_HOURS = 24
_DGA_SCAN_LIMIT = 20000          # 单轮 DGA 扫描上限（防极端情况长跑）
_TUNNEL_MIN_SUBDOMAINS = 20      # 隧道评分门槛（子域数不足不评，降噪）


# ---------------------------------------------------------------------------
# 结论写入（幂等）
# ---------------------------------------------------------------------------


def _upsert_finding(cur, ftype: str, target: str, score: float,
                    evidence: dict) -> bool:
    """写/更新一条结论；返回是否新建（False = 更新既有 pending）。"""
    ev_json = json.dumps(evidence, ensure_ascii=False)
    cur.execute(
        "SELECT id FROM ai_findings WHERE type=? AND target=? "
        "AND status='pending' LIMIT 1", (ftype, target))
    row = cur.fetchone()
    if row:
        cur.execute(
            "UPDATE ai_findings SET score=?, evidence=?, "
            "updated_at=datetime('now','localtime') WHERE id=?",
            (score, ev_json, row["id"]))
        return False
    cur.execute(
        "INSERT INTO ai_findings (type, target, score, evidence) "
        "VALUES (?, ?, ?, ?)", (ftype, target, score, ev_json))
    return True


def _scan_new_domains(window_hours: int) -> list:
    """取窗口内的首现域名（domain, first_client, qtype）。"""
    with db_cursor() as cur:
        cur.execute(
            """SELECT domain, first_client, qtype FROM domain_first_seen
               WHERE first_seen >= datetime('now','localtime', ?)
               ORDER BY first_seen DESC LIMIT ?""",
            (f"-{int(window_hours)} hours", _DGA_SCAN_LIMIT))
        return cur.fetchall()


def run_analysis(window_hours: int = _DEFAULT_WINDOW_HOURS,
                 dga_threshold: float | None = None,
                 tunnel_threshold: float | None = None) -> dict:
    """跑一轮 DGA + 隧道分析，产出结论入库。返回统计（供日志/测试）。"""
    dh = ai_analysis.DGA_THRESHOLD if dga_threshold is None else dga_threshold
    th = ai_analysis.TUNNEL_THRESHOLD if tunnel_threshold is None else tunnel_threshold

    stats = {"dga_scanned": 0, "dga_found": 0, "dga_new": 0,
             "tunnel_groups": 0, "tunnel_found": 0, "tunnel_new": 0}

    rows = _scan_new_domains(window_hours)

    # ---- 1) DGA ----
    dga_hits = []
    for r in rows:
        stats["dga_scanned"] += 1
        score, ev = ai_analysis.dga_score(r["domain"])
        if score >= dh:
            dga_hits.append((r["domain"], score, ev))

    # ---- 2) 隧道聚合 ----
    groups = defaultdict(lambda: {"subs": [], "qts": []})
    for r in rows:
        d = r["domain"] or ""
        if d.count(".") < 2:                  # 无子域不参与隧道分析
            continue
        parent = ai_analysis.registrable_parent(d)
        if not parent:
            continue
        key = (r["first_client"] or "", parent)
        groups[key]["subs"].append(d)
        groups[key]["qts"].append(r["qtype"] or "A")

    tun_hits = []
    for (client, parent), g in groups.items():
        if len(g["subs"]) < _TUNNEL_MIN_SUBDOMAINS:
            continue
        stats["tunnel_groups"] += 1
        score, ev = ai_analysis.tunnel_score(g["subs"], g["qts"])
        if score >= th:
            target = f"{client}|{parent}"
            tun_hits.append((target, score, ev))

    # ---- 3) 入库（同一事务，幂等） ----
    with db_cursor() as cur:
        for domain, score, ev in dga_hits:
            if _upsert_finding(cur, "dga_suspect", domain, score, ev):
                stats["dga_new"] += 1
        stats["dga_found"] = len(dga_hits)
        for target, score, ev in tun_hits:
            if _upsert_finding(cur, "tunnel_suspect", target, score, ev):
                stats["tunnel_new"] += 1
        stats["tunnel_found"] = len(tun_hits)

    return stats


def findings_summary() -> dict:
    """结论概览（各类型待确认数）。"""
    with db_cursor() as cur:
        cur.execute(
            """SELECT type, COUNT(*) AS n FROM ai_findings
               WHERE status='pending' GROUP BY type""")
        return {r["type"]: r["n"] for r in cur.fetchall()}


# ---------------------------------------------------------------------------
# 后台定时线程
# ---------------------------------------------------------------------------

_STOP = threading.Event()
_THREAD: threading.Thread | None = None
_LAST_RUN = {"at": 0.0, "stats": {}}


def _loop() -> None:
    # 启动先等一轮间隔（避免与进程启动争资源）
    while not _STOP.is_set():
        interval = max(5, int(getattr(CONFIG, "ai_analysis_interval_minutes", 30)))
        _STOP.wait(interval * 60)
        if _STOP.is_set():
            break
        if not getattr(CONFIG, "ai_analysis_enabled", True):
            continue
        try:
            stats = run_analysis()
            _LAST_RUN["at"] = time.monotonic()
            _LAST_RUN["stats"] = stats
            if stats.get("dga_found") or stats.get("tunnel_found"):
                logger.info("AI 分析完成：DGA %s/%s 疑似、隧道 %s/%s 组疑似",
                            stats["dga_found"], stats["dga_scanned"],
                            stats["tunnel_found"], stats["tunnel_groups"])
        except Exception:
            logger.exception("AI 批处理失败（下轮重试）")


def start() -> None:
    """启动后台定时分析线程（进程入口调用，幂等）。"""
    global _THREAD
    if _THREAD is not None and _THREAD.is_alive():
        return
    _STOP.clear()
    _THREAD = threading.Thread(target=_loop, name="ai-batch", daemon=True)
    _THREAD.start()
    logger.info("AI 旁路批处理线程已启动（间隔 %s 分钟）",
                getattr(CONFIG, "ai_analysis_interval_minutes", 30))


def stop() -> None:
    _STOP.set()
    if _THREAD is not None:
        _THREAD.join(timeout=5)


def last_run() -> dict:
    st = dict(_LAST_RUN["stats"])
    st["at"] = _LAST_RUN["at"]
    return st
