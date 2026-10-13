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
_FP_WINDOW_HOURS = 72            # 误报识别窗口（3 天，覆盖重试与多客户端）
_FP_MIN_CLIENTS = 3              # 误报识别门槛：至少 3 个客户端共访
_FP_MAX_CANDIDATES = 200         # 单轮误报候选上限


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


def analyze_false_positive(window_hours: int = _FP_WINDOW_HOURS,
                           min_clients: int = _FP_MIN_CLIENTS,
                           threshold: float | None = None) -> list[tuple]:
    """误报识别（P1-1）：被拦域名中识别疑似误伤。

    信号（详见 ai_analysis.false_positive_score）：多客户端共访、被拦后
    重试、工作时间集中、域名年龄、曾正常放行、业务词命中。
    只处理非 IP 后置类拦截（ip_filter 语义不同）。

    返回 [(domain, score, evidence)]，供调用方入库。
    """
    th = ai_analysis.FP_THRESHOLD if threshold is None else threshold
    with db_cursor() as cur:
        cur.execute(
            """SELECT domain,
                      COUNT(DISTINCT client_ip) AS clients,
                      COUNT(*) AS hits,
                      SUM(CASE WHEN CAST(strftime('%H', timestamp) AS INTEGER)
                               BETWEEN 9 AND 18 THEN 1 ELSE 0 END) AS work_hits
               FROM filter_log
               WHERE action='intercept'
                 AND timestamp >= datetime('now','localtime', ?)
                 AND client_ip <> '' AND domain <> ''
                 AND filter_reason NOT LIKE 'ip_filter%'
               GROUP BY domain
               HAVING clients >= ?
               ORDER BY clients DESC, hits DESC LIMIT ?""",
            (f"-{int(window_hours)} hours", int(min_clients),
             _FP_MAX_CANDIDATES))
        rows = cur.fetchall()
    if not rows:
        return []

    domains = [r["domain"] for r in rows]
    # 批量取域名年龄（RDAP 缓存）与"曾正常放行"标记
    ages: dict[str, int | None] = {}
    seen: set[str] = set()
    with db_cursor() as cur:
        chunk = 400
        for i in range(0, len(domains), chunk):
            part = domains[i:i + chunk]
            marks = ",".join("?" * len(part))
            cur.execute(
                f"SELECT domain, registered_at FROM nrd_cache "
                f"WHERE domain IN ({marks})", part)
            for r in cur.fetchall():
                try:
                    from datetime import datetime, timezone
                    reg = datetime.fromisoformat(
                        r["registered_at"]).replace(tzinfo=timezone.utc)
                    ages[r["domain"]] = (
                        datetime.now(timezone.utc) - reg).days
                except (ValueError, TypeError):
                    ages[r["domain"]] = None
            cur.execute(
                f"SELECT domain FROM domain_first_seen "
                f"WHERE domain IN ({marks})", part)
            seen.update(row["domain"] for row in cur.fetchall())

    hits = []
    for r in rows:
        d = r["domain"]
        hits_n = r["hits"] or 0
        hour_ratio = (r["work_hits"] or 0) / hits_n if hits_n else 0.0
        score, ev = ai_analysis.false_positive_score(
            clients=r["clients"] or 0, hits=hits_n, hour_ratio=hour_ratio,
            domain_age_days=ages.get(d), in_first_seen=d in seen,
            label=ai_analysis.label_of(d))
        if score >= th:
            hits.append((d, score, ev))
    hits.sort(key=lambda x: -x[1])
    return hits


def analyze_threat_clusters(window_hours: int = _DEFAULT_WINDOW_HOURS,
                            min_hits: int = 3,
                            top_n: int = 50) -> list[tuple]:
    """告警聚类（P1-2）：把海量拦截记录聚成"威胁族群"。

    聚类键 = 可注册父域（同一恶意基础设施的多个子域归为一族），
    族群画像含：拦截次数、独立域名数、独立客户端数、命中源分布、
    时间跨度与样例域名——把"今天 20 万条拦截"压缩成"今日 N 个族群"。

    返回 [(parent, score, evidence)]，score 按族群规模归一（0.3~1.0）。
    """
    from collections import Counter, defaultdict
    with db_cursor() as cur:
        cur.execute(
            """SELECT domain, client_ip, filter_reason, source_api
               FROM filter_log
               WHERE action IN ('intercept', 'remove_ip')
                 AND timestamp >= datetime('now','localtime', ?)
                 AND domain <> ''""",
            (f"-{int(window_hours)} hours",))
        rows = cur.fetchall()
    if not rows:
        return []

    groups: dict = defaultdict(lambda: {
        "hits": 0, "domains": set(), "clients": set(), "sources": Counter()})
    for r in rows:
        parent = ai_analysis.registrable_parent(r["domain"])
        if not parent:
            continue
        g = groups[parent]
        g["hits"] += 1
        g["domains"].add(r["domain"])
        if r["client_ip"]:
            g["clients"].add(r["client_ip"])
        src = r["source_api"] or r["filter_reason"] or "unknown"
        g["sources"][src] += 1

    clusters = []
    for parent, g in groups.items():
        if g["hits"] < min_hits:
            continue
        clusters.append({
            "parent": parent,
            "hits": g["hits"],
            "domain_count": len(g["domains"]),
            "client_count": len(g["clients"]),
            "sources": dict(g["sources"].most_common(5)),
            "sample_domains": sorted(g["domains"])[:5],
        })
    if not clusters:
        return []
    clusters.sort(key=lambda c: (-c["hits"], c["parent"]))
    max_hits = clusters[0]["hits"]
    out = []
    for c in clusters[:top_n]:
        # 规模归一：最大族群 1.0，最小（min_hits）保底 0.3
        score = round(min(1.0, 0.3 + 0.7 * (c["hits"] / max_hits)), 4)
        ev = dict(c)
        ev["threshold"] = min_hits
        ev["window_hours"] = window_hours
        out.append((c["parent"], score, ev))
    return out


def run_analysis(window_hours: int = _DEFAULT_WINDOW_HOURS,
                 dga_threshold: float | None = None,
                 tunnel_threshold: float | None = None) -> dict:
    """跑一轮 DGA + 隧道 + 误报 + 族群分析，产出结论入库。返回统计。"""
    dh = ai_analysis.DGA_THRESHOLD if dga_threshold is None else dga_threshold
    th = ai_analysis.TUNNEL_THRESHOLD if tunnel_threshold is None else tunnel_threshold

    stats = {"dga_scanned": 0, "dga_found": 0, "dga_new": 0,
             "tunnel_groups": 0, "tunnel_found": 0, "tunnel_new": 0,
             "fp_found": 0, "fp_new": 0,
             "clusters_found": 0, "clusters_new": 0}

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

    # ---- 3) 误报识别（独立窗口：3 天，覆盖重试与多客户端共访） ----
    fp_hits = analyze_false_positive()

    # ---- 4) 告警聚类（威胁族群） ----
    cluster_hits = analyze_threat_clusters(window_hours=window_hours)

    # ---- 5) 入库（同一事务，幂等） ----
    with db_cursor() as cur:
        for domain, score, ev in dga_hits:
            if _upsert_finding(cur, "dga_suspect", domain, score, ev):
                stats["dga_new"] += 1
        stats["dga_found"] = len(dga_hits)
        for target, score, ev in tun_hits:
            if _upsert_finding(cur, "tunnel_suspect", target, score, ev):
                stats["tunnel_new"] += 1
        stats["tunnel_found"] = len(tun_hits)
        for domain, score, ev in fp_hits:
            if _upsert_finding(cur, "false_positive", domain, score, ev):
                stats["fp_new"] += 1
        stats["fp_found"] = len(fp_hits)
        for parent, score, ev in cluster_hits:
            if _upsert_finding(cur, "threat_cluster", parent, score, ev):
                stats["clusters_new"] += 1
        stats["clusters_found"] = len(cluster_hits)

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
            if (stats.get("dga_found") or stats.get("tunnel_found")
                    or stats.get("fp_found") or stats.get("clusters_found")):
                logger.info(
                    "AI 分析完成：DGA %s/%s、隧道 %s/%s 组、误报 %s、族群 %s",
                    stats["dga_found"], stats["dga_scanned"],
                    stats["tunnel_found"], stats["tunnel_groups"],
                    stats["fp_found"], stats["clusters_found"])
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
