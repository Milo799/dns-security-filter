"""AI 旁路分析算法（迭代 49 · AI 能力规划 P0-2/P0-3）。

纯算法模块：**无 DB 依赖、无网络依赖、无第三方模型依赖**，可独立单元测试。

设计原则：
  - **可解释优先**：所有评分同时输出"证据"（各特征贡献明细），
    安全人员能看到"为什么判它可疑"，而非黑盒分数；
  - **零依赖**：DGA 用字符 bigram 语言模型（内置正常域名样本训练）
    + 统计特征，无需 GPU / 无需外部模型文件 / 冷启动即可用；
  - **红线**：本模块只产出评分与证据，**绝不参与拦截判定**——
    由 ai_batch 落 ai_findings 表，人工确认后才可能回灌名单。

两个能力：
  - dga_score(domain)                → DGA（域名自动生成算法）嫌疑评分
  - tunnel_score(subdomains, qtypes) → DNS 隧道（数据外泄隐蔽信道）嫌疑评分
"""

import math
from collections import Counter

# ---------------------------------------------------------------------------
# 通用字符统计
# ---------------------------------------------------------------------------


def shannon_entropy(s: str) -> float:
    """Shannon 熵（bits/字符）。正常英文词约 2.5~3.2，DGA 常 > 3.5。"""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


_VOWELS = set("aeiou")


def _longest_consonant_run(s: str) -> int:
    """最长连续辅音长度（正常英文域名极少出现 4 连辅音）。"""
    best = cur = 0
    for ch in s:
        if ch.isalpha() and ch not in _VOWELS:
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


def _digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(ch.isdigit() for ch in s) / len(s)


def _vowel_ratio(s: str) -> float:
    letters = [ch for ch in s if ch.isalpha()]
    if not letters:
        return 0.0
    return sum(ch in _VOWELS for ch in letters) / len(letters)


def label_of(domain: str) -> str:
    """取域名主标签（去掉 TLD 与子域，只看注册名部分）。

    a.b.example.com → example；example.com → example；单标签原样返回。
    """
    d = (domain or "").rstrip(".").lower()
    parts = [p for p in d.split(".") if p]
    if len(parts) >= 2:
        return parts[-2]
    return parts[0] if parts else ""


def registrable_parent(domain: str) -> str:
    """取可注册父域（domain 的最后两段）：a.b.example.com → example.com。

    简化实现（不做公共后缀表）：对 DNS 隧道检测足够——隧道域名通常
    挂在攻击者自有父域下（xxx.evil.com），最后两段即父域。
    """
    parts = [p for p in (domain or "").rstrip(".").lower().split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else (parts[0] if parts else "")


# ---------------------------------------------------------------------------
# DGA 检测：字符 bigram 语言模型 + 统计特征
# ---------------------------------------------------------------------------

# 内置正常域名样本（常见站点名 + 常见业务词）——用于训练 bigram 模型。
# 刻意不含 DGA 特征串，保证模型衡量的是"像不像人起的名字"。
_NORMAL_SAMPLES = (
    # 常见站点/品牌
    "google youtube facebook baidu taobao amazon wikipedia twitter instagram "
    "linkedin microsoft apple netflix office adobe oracle salesforce dropbox "
    "slack github gitlab stackoverflow cloudflare akamai alibaba tencent weibo "
    "zhihu douban meituan jd pinduoduo alipay wechat dingtalk feishu xiaomi "
    "huawei samsung sony lenovo dell intel nvidia amd cisco vmware redhat "
    # 常见业务/技术词
    "mail email shop shopify store news blog cloud app web webapp data api "
    "cdn static image images img video videos music music123 game games play "
    "test testing dev develop stage staging prod production demo sample "
    "login signin signup account accounts profile user users member admin "
    "service services server servers support help helpdesk docs doc wiki "
    "portal secure security auth oauth token sso vpn proxy gateway edge "
    "online site website page pages home index main default app1 mobile "
    "media group network systems solutions digital global central "
    "analytics report reporting dashboard monitor monitoring status health "
    "payment payments billing invoice order orders cart checkout delivery "
    "search maps travel hotel flight booking ticket event events news sport "
    "career jobs recruit hr finance legal marketing sales partner channel "
    "learn education course training academy school university library "
    "healthcare hospital clinic doctor patient medical pharmacy health "
    "food recipe restaurant kitchen menu coffee cafe hotel resort travel"
).split()


def _train_bigram() -> dict[str, float]:
    """从正常样本训练字符 bigram 频率（含起止标记）。"""
    counts: Counter = Counter()
    total = 0
    for w in _NORMAL_SAMPLES:
        s = "^" + w + "$"
        for i in range(len(s) - 1):
            counts[s[i:i + 2]] += 1
            total += 1
    return {g: c / total for g, c in counts.items()}


_BIGRAMS = _train_bigram()
# 未登录 bigram 的默认概率：取最低频率的 1/10（避免 log(0)）
_FLOOR = min(_BIGRAMS.values()) / 10 if _BIGRAMS else 1e-6


def bigram_logprob(label: str) -> float:
    """主标签的平均 bigram 对数概率（越负越不像正常域名）。"""
    if not label:
        return -20.0
    s = "^" + label + "$"
    n = len(s) - 1
    if n <= 0:
        return -20.0
    return sum(math.log(_BIGRAMS.get(s[i:i + 2], _FLOOR))
               for i in range(n)) / n


# 各特征权重（合计 1.0）；阈值与权重经正常样本/已知 DGA 家族样本校准
_W = {"len": 0.14, "digit": 0.16, "entropy": 0.18,
      "consonant": 0.14, "vowel": 0.13, "bigram": 0.25}

DGA_THRESHOLD = 0.55      # 综合分 >= 此值判"疑似 DGA"（校准：正常域 ≤0.2）


def dga_score(domain: str) -> tuple[float, dict]:
    """DGA 嫌疑评分（0~1，越高越可疑）+ 可解释证据。

    证据 dict 含每个特征的原始值与贡献分，供 ai_findings.evidence 落库。
    """
    label = label_of(domain)
    if not label:
        return 0.0, {"label": "", "note": "empty label"}

    # 特征归一化到 0~1（0=正常，1=极可疑）
    f_len = min(1.0, max(0.0, (len(label) - 8) / 12.0))          # >8 起评
    f_digit = min(1.0, _digit_ratio(label) / 0.4)                # 40% 数字满分
    ent = shannon_entropy(label)
    f_ent = min(1.0, max(0.0, (ent - 3.0) / 1.5))                # 3.0 起评
    cr = _longest_consonant_run(label)
    f_con = min(1.0, max(0.0, (cr - 3) / 3.0))                   # 4 连起评
    vr = _vowel_ratio(label)
    f_vow = min(1.0, max(0.0, (0.25 - vr) / 0.25))               # 元音<25% 起评
    lp = bigram_logprob(label)
    # 实测分布：正常域名 -4.9~-6.2（均值约 -5.5），DGA -7.2~-9.1
    # → -6.0 起评、-9.0 满分（线性映射，校准自内置样本 + 模拟 DGA）
    f_big = min(1.0, max(0.0, (-6.0 - lp) / 3.0))

    feats = {"len": f_len, "digit": f_digit, "entropy": f_ent,
             "consonant": f_con, "vowel": f_vow, "bigram": f_big}
    score = sum(_W[k] * v for k, v in feats.items())

    evidence = {
        "label": label,
        "len": len(label),
        "digit_ratio": round(_digit_ratio(label), 3),
        "entropy": round(ent, 3),
        "consonant_run": cr,
        "vowel_ratio": round(vr, 3),
        "bigram_logprob": round(lp, 3),
        "contributions": {k: round(_W[k] * v, 4) for k, v in feats.items()},
        "threshold": DGA_THRESHOLD,
    }
    return round(score, 4), evidence


# ---------------------------------------------------------------------------
# DNS 隧道检测：子域结构 + 查询类型 + 频次
# ---------------------------------------------------------------------------

TUNNEL_THRESHOLD = 0.60   # 综合分 >= 此值判"疑似隧道"


def tunnel_score(subdomains: list[str], qtypes: list[str]) -> tuple[float, dict]:
    """DNS 隧道嫌疑评分（0~1）+ 证据。

    输入：同一 (客户端, 父域) 在一个时间窗内的子域列表与查询类型列表。
    数据外泄的典型特征：海量子域、子域超长且高熵、TXT/NULL 等异常类型。

    证据含各维原始值（标签数/平均长度/平均熵/异常类型比），供人工研判。
    """
    n = len(subdomains)
    if n == 0:
        return 0.0, {"queries": 0, "note": "no queries"}

    # 取每个子域相对父域的前缀（a.b.evil.com → a.b）
    prefixes = []
    for d in subdomains:
        parts = [p for p in (d or "").rstrip(".").lower().split(".") if p]
        prefixes.append(".".join(parts[:-2]) if len(parts) > 2 else parts[0])
    prefixes = [p for p in prefixes if p]
    if not prefixes:
        return 0.0, {"queries": n, "note": "no subdomain prefix"}

    avg_len = sum(len(p) for p in prefixes) / len(prefixes)
    avg_ent = sum(shannon_entropy(p) for p in prefixes) / len(prefixes)
    uniq_ratio = len(set(prefixes)) / len(prefixes)     # 子域唯一性（隧道多为唯一）

    # 异常查询类型占比（正常业务几乎只有 A/AAAA/CNAME/MX/NS）
    abnormal = {"TXT", "NULL", "ANY", "SRV", "CNAME", "PTR", "SOA", "HINFO"}
    bad_type = sum(1 for t in qtypes if (t or "").upper() in abnormal)
    bad_ratio = bad_type / max(1, len(qtypes))

    # 归一化（0=正常，1=极可疑）
    f_vol = min(1.0, max(0.0, (n - 20) / 130.0))            # 20 次起评，150 满分
    f_len = min(1.0, max(0.0, (avg_len - 12) / 28.0))       # 12 字符起评
    f_ent = min(1.0, max(0.0, (avg_ent - 3.2) / 1.3))       # 3.2 起评
    f_uniq = min(1.0, max(0.0, (uniq_ratio - 0.6) / 0.4))   # 唯一性 60% 起评
    f_type = min(1.0, bad_ratio / 0.3)                      # 异常类型 30% 满分

    w = {"vol": 0.22, "len": 0.22, "ent": 0.20, "uniq": 0.16, "type": 0.20}
    feats = {"vol": f_vol, "len": f_len, "ent": f_ent,
             "uniq": f_uniq, "type": f_type}
    score = sum(w[k] * v for k, v in feats.items())

    evidence = {
        "queries": n,
        "unique_prefixes": len(set(prefixes)),
        "avg_prefix_len": round(avg_len, 2),
        "avg_entropy": round(avg_ent, 3),
        "abnormal_type_ratio": round(bad_ratio, 3),
        "type_counter": dict(Counter(t.upper() for t in qtypes).most_common(5)),
        "sample_prefixes": prefixes[:3],
        "contributions": {k: round(w[k] * v, 4) for k, v in feats.items()},
        "threshold": TUNNEL_THRESHOLD,
    }
    return round(score, 4), evidence


# ---------------------------------------------------------------------------
# 误报识别（P1-1）：被拦域名中识别"疑似误伤"（多客户端共访等业务特征）
# ---------------------------------------------------------------------------

# 业务/通用词——出现在主标签里说明更像正常业务域名（与 DGA 特征相反）
_BIZ_WORDS = frozenset("""
mail email shop store news blog cloud app web data api cdn static image img
video music game games play test dev demo login signin account user admin
service server support help docs wiki portal secure auth token sso vpn
proxy gateway edge online site website page home index main mobile media
group network systems solutions digital global central analytics report
dashboard monitor status health payment billing invoice order cart checkout
search maps travel hotel flight booking ticket event events sport career
jobs recruit hr finance legal marketing sales partner channel learn
education course training academy school university library healthcare
hospital clinic doctor medical pharmacy food recipe restaurant kitchen menu
coffee cafe resort office update download upload sync backup restore
""".split())

FP_THRESHOLD = 0.55       # 误报综合分 >= 此值 → 疑似误伤，建议加白


def false_positive_score(clients: int, hits: int, hour_ratio: float,
                         domain_age_days: int | None = None,
                         in_first_seen: bool = False,
                         label: str = "") -> tuple[float, dict]:
    """误伤嫌疑评分（0~1）+ 可解释证据。

    参数（由 ai_batch 从 filter_log / nrd_cache / domain_first_seen 聚合）：
      clients          独立客户端数（多客户端共访 = 业务常用，最强误伤信号）
      hits             拦截总次数
      hour_ratio       09-18 点拦截占比（业务流量时间规律）
      domain_age_days  已知注册年龄（None = 未知，中性）
      in_first_seen    该域名曾在首现表（历史解析成功过）
      label            主标签（业务词匹配）

    证据含各特征原值与贡献分，供人工研判。
    """
    # 1) 多客户端共访：3 个起评、10+ 满分（最强信号，权重最高）
    f_clients = min(1.0, max(0.0, (clients - 2) / 8.0))
    # 2) 人均重试：被拦后仍反复访问 → 用户依赖该域
    per = hits / max(1, clients)
    f_retry = min(1.0, max(0.0, (per - 1.2) / 3.0))
    # 3) 工作时间集中度：业务流量多在 09-18
    f_hours = min(1.0, max(0.0, hour_ratio))
    # 4) 域名年龄：老域名基本排除"新注册恶意"（未知取中性 0.5）
    if domain_age_days is None:
        f_age = 0.5
    elif domain_age_days > 730:
        f_age = 1.0
    elif domain_age_days > 180:
        f_age = 0.7
    elif domain_age_days > 30:
        f_age = 0.4
    else:
        f_age = 0.0
    # 5) 曾被正常放行（首现表）——历史业务使用证据
    f_seen = 1.0 if in_first_seen else 0.0
    # 6) 业务词命中
    lab = (label or "").lower()
    biz_hit = any(w in lab for w in _BIZ_WORDS) if lab else False
    f_biz = 1.0 if biz_hit else 0.0

    w = {"clients": 0.32, "retry": 0.18, "hours": 0.15,
         "age": 0.15, "seen": 0.12, "biz": 0.08}
    feats = {"clients": f_clients, "retry": f_retry, "hours": f_hours,
             "age": f_age, "seen": f_seen, "biz": f_biz}
    score = sum(w[k] * v for k, v in feats.items())

    evidence = {
        "clients": clients,
        "hits": hits,
        "hits_per_client": round(per, 2),
        "work_hour_ratio": round(hour_ratio, 3),
        "domain_age_days": domain_age_days,
        "in_first_seen": in_first_seen,
        "biz_label_hit": biz_hit,
        "contributions": {k: round(w[k] * v, 4) for k, v in feats.items()},
        "threshold": FP_THRESHOLD,
    }
    return round(score, 4), evidence


# ---------------------------------------------------------------------------
# 客户端行为异常（P2）：失陷主机识别
# ---------------------------------------------------------------------------

ANOMALY_THRESHOLD = 0.58  # 异常综合分 >= 此值 → 疑似失陷/异常主机


def client_anomaly_score(new_domains: int, intercepts: int, parents: int,
                         baseline_new: float = 0.0) -> tuple[float, dict]:
    """客户端行为异常评分（0~1）+ 证据。

    参数（由 ai_batch 从首现表/拦截日志按客户端聚合）：
      new_domains   窗口内该客户端首现域名数
      intercepts    窗口内该客户端拦截命中数
      parents       涉及的独立父域数
      baseline_new  同窗口全体客户端新域名数的中位数（横截面基线）

    失陷特征：突发大量新域名（相对全网基线）、拦截命中高、
    父域分散。三项特征均已可测（不做无法测量的"新域名占比"推测）。
    """
    # 1) 新域名规模相对全网基线的偏离（横截面，冷启动即可用）
    if baseline_new > 0:
        f_scale = min(1.0, max(0.0, (new_domains / baseline_new - 3) / 17.0))
    else:
        f_scale = min(1.0, max(0.0, new_domains / 300.0))
    # 2) 拦截命中数：命中越多越可疑（真实业务很少被大量拦截）
    f_int = min(1.0, max(0.0, intercepts / 40.0))
    # 3) 父域分散度：正常客户端集中在少数常用父域
    f_parents = min(1.0, max(0.0, (parents - 25) / 175.0))

    w = {"scale": 0.38, "intercept": 0.34, "parents": 0.28}
    feats = {"scale": f_scale, "intercept": f_int, "parents": f_parents}
    score = sum(w[k] * v for k, v in feats.items())

    evidence = {
        "new_domains": new_domains,
        "intercepts": intercepts,
        "parents": parents,
        "baseline_new_median": round(baseline_new, 1),
        "contributions": {k: round(w[k] * v, 4) for k, v in feats.items()},
        "threshold": ANOMALY_THRESHOLD,
    }
    return round(score, 4), evidence
