"""域名层级判定与人工名单通配符风险防护（Task #176，迭代 29）。

背景（2026-09-04 用户需求）：人工黑白名单支持 *.xxx.com 通配符且
匹配语义为"后缀匹配全部子域"——若加入 *.com / *.cn 这类裸公共后缀：
  - 白名单 *.com  → 绕过全部检测放行几乎整个互联网（安全风险）
  - 黑名单 *.com  → 拦截几乎整个互联网（可用性灾难）
两条都是巨大风险，必须在入口拦截 + 列表可按层级筛选排查。

层级口径（公共后缀感知）：
  - 顶层通配（*.com / *.com.cn）    → 后缀即公共后缀 → 拒绝
  - 主域级（example.com / *.example.com）→ 可注册域（eTLD+1）及
    其父域通配 → 允许，标记"父域级通配"警示（影响整个站点）
  - 子域级（a.example.com / *.a.example.com）→ 更深层级 → 允许
  - 筛选口径：tld=一级(公共后缀本身) / registrable=主域(可注册域) /
    subdomain=子域（比可注册域更深）

离线公共后缀表：内置常见 gTLD/ccTLD/多级后缀（com.cn/org.cn/gov.cn
等）+ 新 gTLD（app/dev/io 等）。完整 PSL（publicsuffix.org，约
9500 行）作为可选增强：放入 data/public_suffix_list.dat 即自动加载
（按需更新，不联网）——内置表未命中时回退 PSL 文件，再回退"两级
启发式"（取最后两段作可注册域，多级后缀场景 com.cn 会被算成
example.com.cn 的可注册域，属保守方向：宁可多警示不少拦截）。
"""

import re
import threading
from pathlib import Path

_LOCK = threading.Lock()
_PSL_CACHE: frozenset[str] | None = None

# 内置公共后缀（离线兜底；PSL 文件存在时自动合并）
_BUILTIN_PSL: frozenset[str] = frozenset({
    # 通用顶级域
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz",
    "name", "pro", "museum", "coop", "aero", "xyz", "top", "online",
    "site", "club", "shop", "store", "tech", "app", "dev", "io",
    "ai", "me", "tv", "cc", "co", "biz", "cloud", "live", "life",
    "ltd", "group", "team", "work", "wiki", "zip", "mov", "link",
    "click", "icu", "fun", "wang", "win", "red", "asia", "cat",
    "jobs", "mobi", "tel", "travel", "arpa",
    # 常见国家及地区顶级域
    "cn", "us", "uk", "jp", "kr", "de", "fr", "ru", "in", "br",
    "au", "ca", "it", "es", "nl", "se", "no", "fi", "dk", "pl",
    "ch", "at", "be", "cz", "gr", "hu", "pt", "ro", "tr", "ua",
    "mx", "ar", "cl", "co.uk", "my", "sg", "th", "vn", "ph", "id",
    "hk", "mo", "tw",
    # 中国多级公共后缀（PSL 官方列全 25 个，这里收全）
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "mil.cn", "bj.cn", "sh.cn", "tj.cn", "cq.cn", "he.cn", "sx.cn",
    "nm.cn", "ln.cn", "jl.cn", "hl.cn", "js.cn", "zj.cn", "ah.cn",
    "fj.cn", "jx.cn", "sd.cn", "ha.cn", "hb.cn", "hn.cn", "gd.cn",
    "gx.cn", "hi.cn", "sc.cn", "gz.cn", "yn.cn", "xz.cn", "sn.cn",
    "gs.cn", "qh.cn", "nx.cn", "xj.cn", "tw.cn", "hk.cn", "mo.cn",
    # 其他常见多级公共后缀
    "com.hk", "com.tw", "com.mo", "com.sg", "com.my", "com.jp",
    "com.kr", "com.au", "com.br", "com.mx", "com.ar", "com.cn",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "or.jp", "ne.jp",
    "go.jp", "ac.jp", "co.kr", "or.kr", "go.id", "co.id", "or.id",
    "web.id", "co.in", "net.in", "org.in", "co.za", "com.tr",
    "com.ru", "net.ru", "org.ru", "com.ua", "net.ua", "org.ua",
    "com.vn", "com.br", "com.mx", "gob.mx", "com.ar", "com.co",
    "com.pe", "com.ve", "com.ec", "com.py", "com.uy", "com.bo",
    "com.do", "com.gt", "com.sv", "com.ni", "com.pa", "com.cr",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz",
    "com.ph", "com.pk", "com.bd", "com.tr", "com.sa", "com.eg",
    "com.ng", "com.ke", "com.gh", "com.tw", "idv.tw", "org.tw",
})

# 值形态校验（比 PSL 更宽松的语法白名单：字母数字-连字符段）
_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
# punycode 域名（xn--xxx）
_XN_RE = re.compile(r"^xn--[a-z0-9-]+$")

# 表列宽（.dat 文件每行后缀）
_PSL_PATH = Path(__file__).resolve().parent.parent / "data" / \
    "public_suffix_list.dat"


def _load_psl() -> frozenset[str]:
    """内置表 + 可选 PSL 文件合并（进程内缓存一次）。"""
    global _PSL_CACHE
    with _LOCK:
        if _PSL_CACHE is not None:
            return _PSL_CACHE
        psl = set(_BUILTIN_PSL)
        if _PSL_PATH.is_file():
            try:
                for line in _PSL_PATH.read_text(
                        encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line or line.startswith("//"):
                        continue
                    psl.add(line.lower().lstrip("*."))
            except OSError:
                pass   # 文件读失败退回内置表
        _PSL_CACHE = frozenset(psl)
        return _PSL_CACHE


def public_suffix(domain: str) -> str:
    """返回域名的公共后缀（最右侧命中的 PSL 条目，支持多级）。

    例：a.example.com.cn → com.cn；a.example.com → com。
    未命中 PSL 时回退最后一段（启发式，与浏览器行为一致的保守方向）。
    """
    d = normalize_domain(domain)
    if not d:
        return ""
    labels = d.split(".")
    n = len(labels)
    if n == 1:
        return labels[0]
    # 从最长的可能后缀开始向短探测（多级后缀优先）。
    # 上界取 n（含域名本身）：com.cn / example.com 等域名自身
    # 即公共后缀/候选的场景必须可命中（Task #176 自测踩坑）。
    for take in range(min(n, 5), 0, -1):
        cand = ".".join(labels[n - take:])
        if cand in _load_psl():
            return cand
    return labels[-1]


def registrable_domain(domain: str) -> str:
    """可注册域（eTLD+1）：公共后缀 + 其上一段。

    例：a.example.com.cn → example.com.cn；a.example.com → example.com。
    域名本身即是公共后缀（com / com.cn）时返回空串。
    """
    d = normalize_domain(domain)
    if not d:
        return ""
    ps = public_suffix(d)
    if not ps or d == ps:
        return ""
    suffix_len = len(ps.split("."))
    labels = d.split(".")
    if len(labels) <= suffix_len:
        return ""
    return ".".join(labels[-(suffix_len + 1):])


def normalize_domain(domain: str) -> str:
    """清洗：去空白/尾点/协议头/通配前缀，转小写。空值返回 ''。"""
    d = (domain or "").strip().lower().rstrip(".")
    if "://" in d:
        d = d.split("://", 1)[1]
    if d.startswith("*."):
        d = d[2:]
    elif d.startswith("*"):
        d = d.lstrip("*").lstrip(".")
    if "/" in d:
        d = d.split("/", 1)[0]
    return d.strip()


def is_valid_domain_syntax(domain: str) -> bool:
    """宽松语法校验：各段符合 hostname 规则（支持 punycode）。"""
    d = normalize_domain(domain)
    if not d or len(d) > 253:
        return False
    labels = d.split(".")
    if len(labels) < 2 and not d.startswith("localhost"):
        # 单段（如 localhost / 内网单标签）放行——内网环境常见
        pass
    return all(_LABEL_RE.match(lb) or _XN_RE.match(lb)
               or lb == "localhost" for lb in labels)


def classify_entry(target: str, value: str) -> dict:
    """名单条目分级（创建校验 + 列表展示 + 层级筛选共用）。

    返回：
      {
        "target":   "domain" | "ip",
        "level":    "tld" | "registrable" | "subdomain" | "ip" | "",
        "wildcard": bool,          # 是否 *. 前缀通配
        "risk":     "blocked" | "warn" | "",   # blocked=拒绝入库
        "risk_note": str           # 提示文案
      }

    风险口径：
      blocked  *.com / *.com.cn 等裸公共后缀通配（白名单=绕过全部
               检测，黑名单=全网瘫痪，一律拒绝）；
               以及 * 裸星号、*.（空后缀）这类笔误形态。
      warn     *.example.com 主域级通配（影响整站，保留但列表标黄）
      （子域级通配/精确域名/普通 IP 与 CIDR 无附加风险）
    """
    out = {"target": target, "level": "", "wildcard": False,
           "risk": "", "risk_note": ""}
    v = (value or "").strip()
    if target != "domain":
        out["level"] = "ip"
        return out
    out["wildcard"] = v.lower().startswith("*.")
    d = normalize_domain(v)
    # ---- 形态拒绝：裸星号 / 空后缀（明显笔误） ----
    raw = v.lower().rstrip(".")
    if raw in ("*", "*.", "*."):
        out.update(risk="blocked",
                   risk_note="通配符后缀为空，属于无效条目")
        return out
    if not d:
        out.update(risk="blocked", risk_note="域名格式无效")
        return out
    ps = public_suffix(d)
    labels = d.split(".")
    # ---- 顶层通配拒绝：*.<公共后缀> ----
    if out["wildcard"] and (d == ps):
        out.update(level="tld", risk="blocked",
                   risk_note=f"*.{ps} 是顶层通配——白名单等于放行整个 "
                             f"互联网、黑名单等于拦截整个互联网，禁止添加")
        return out
    # ---- 层级归类 ----
    if d == ps:
        out["level"] = "tld"           # 精确公共后缀（com 本身）
    elif registrable_domain(d) == d:
        out["level"] = "registrable"   # 主域
    else:
        out["level"] = "subdomain"     # 子域
    # ---- 主域级通配警示（允许但提示影响范围） ----
    if out["wildcard"] and out["level"] == "registrable":
        out.update(risk="warn",
                   risk_note="父域级通配：该域名下全部子域都会命中此规则")
    return out
