"""DNS 安全过滤中间件 · MCP 服务（Model Context Protocol）。

目的：把本系统变成 **AI Agent 可直接操作的对象**——任何支持 MCP 的
客户端（WorkBuddy / Claude / IDE Copilot / 自研 Agent）都能用自然语言
查询与操作本平台，而不必人肉翻大屏。

## 架构

    MCP 客户端  ──stdio 或 streamable-http──▶  mcp_server.py
                                                  │  HTTP（Bearer）
                                                  ▼
                                        platform Web API（/api/*）
                                                  │
                                                  ▼
                                     SQLite（策略/日志/结论）+ DNS 进程

- **不直接读写数据库**：全部经平台 Web API——复用其鉴权、参数校验、
  审计留痕与缓存失效逻辑，避免绕过既有防线（红线：不新增旁路写入口）。
- **只读工具**自由调用；**写工具**三重闸门：进程开关 → 调用方显式
  confirm → 平台侧审计。默认写能力开启但每次都需 confirm=true。

## 传输

    DNSF_MCP_TRANSPORT=stdio    （默认，本地 Agent 用，无需鉴权）
    DNSF_MCP_TRANSPORT=http     远端 Agent 用，需 DNSF_MCP_TOKEN

## 环境变量

    DNSF_API_BASE       平台地址，默认 http://127.0.0.1:8080
    DNSF_API_USER       平台账号，默认 admin
    DNSF_API_PASSWORD   平台密码（必填）
    DNSF_MCP_TRANSPORT  stdio | http
    DNSF_MCP_HOST       http 绑定地址，默认 0.0.0.0
    DNSF_MCP_PORT       http 端口，默认 8090
    DNSF_MCP_TOKEN      http 传输的 Bearer Token（http 模式必填）
    DNSF_MCP_ALLOW_WRITE 1/0，默认 1（0 = 只读模式，写工具一律拒绝）
    DNSF_MCP_AGENT      调用方标识（写入审计归属），默认 mcp-agent
    DNSF_MCP_TIMEOUT    单次 API 超时秒，默认 20

## 启动

    python mcp_server.py                 # stdio
    python mcp_server.py --transport http --port 8090

依赖：mcp SDK（见 requirements-mcp.txt）。
"""

from __future__ import annotations

import argparse
import functools
import json
import logging
import os
import socket
import sys
import time
from dataclasses import dataclass, field

logger = logging.getLogger("dnsf.mcp")

SERVER_NAME = "dns-security-filter"
SERVER_VERSION = "1.0.0"

_list_cache_hint = ("生效延迟：平台侧名单缓存 ≤60s 自动重载，"
                    "域名结论缓存 TTL 300s——写操作后建议 60s 再验证")


# ══════════════════════════════════════════════════════════════════════
# 配置
# ══════════════════════════════════════════════════════════════════════


@dataclass
class Settings:
    api_base: str = "http://127.0.0.1:8080"
    api_user: str = "admin"
    api_password: str = ""
    timeout: float = 20.0
    allow_write: bool = False          # 安全默认：只读（写能力必须显式开启）
    agent_name: str = "mcp-agent"
    transport: str = "stdio"
    host: str = "0.0.0.0"
    port: int = 8090
    token: str = ""

    @classmethod
    def from_env(cls, env: dict | None = None) -> "Settings":
        e = os.environ if env is None else env

        def flag(key: str, default: bool) -> bool:
            raw = (e.get(key) or "").strip().lower()
            if not raw:
                return default
            return raw not in ("0", "false", "no", "off")

        return cls(
            api_base=(e.get("DNSF_API_BASE")
                      or "http://127.0.0.1:8080").rstrip("/"),
            api_user=e.get("DNSF_API_USER") or "admin",
            api_password=e.get("DNSF_API_PASSWORD") or "",
            timeout=float(e.get("DNSF_MCP_TIMEOUT") or 20),
            allow_write=flag("DNSF_MCP_ALLOW_WRITE", False),
            agent_name=e.get("DNSF_MCP_AGENT") or "mcp-agent",
            transport=(e.get("DNSF_MCP_TRANSPORT") or "stdio").lower(),
            host=e.get("DNSF_MCP_HOST") or "0.0.0.0",
            port=int(e.get("DNSF_MCP_PORT") or 8090),
            token=e.get("DNSF_MCP_TOKEN") or "",
        )


# ══════════════════════════════════════════════════════════════════════
# HTTP 底层（可替换，便于测试注入）
# ══════════════════════════════════════════════════════════════════════


class ApiError(RuntimeError):
    """平台 API 调用失败（网络异常 / 非 2xx / 业务 code != 0）。"""

    def __init__(self, message: str, status: int = 0, payload=None):
        super().__init__(message)
        self.status = status
        self.payload = payload


def _http(method: str, url: str, *, headers: dict | None = None,
          params: dict | None = None, json_body=None,
          timeout: float = 20.0):
    """真实 HTTP 调用（requests）。返回 (status_code, parsed_json)。

    显式 trust_env=False：平台在内网，环境里的代理变量不应参与
    （生产实测 curl 需 --noproxy '*'，此处等价）。
    """
    import requests
    session = requests.Session()
    session.trust_env = False
    try:
        resp = session.request(method, url, headers=headers, params=params,
                               json=json_body, timeout=timeout)
    finally:
        session.close()
    try:
        payload = resp.json()
    except ValueError:
        payload = {"_raw": resp.text[:500]}
    return resp.status_code, payload


# ══════════════════════════════════════════════════════════════════════
# 平台 API 客户端
# ══════════════════════════════════════════════════════════════════════


class ApiClient:
    """平台 Web API 客户端（自动登录、401 重登一次）。"""

    def __init__(self, settings: Settings):
        self.s = settings
        self._token = ""
        self._login_at = 0.0

    # ---- 鉴权 ----
    def login(self) -> str:
        status, body = _http(
            "POST", self.s.api_base + "/api/auth/login",
            headers={"Content-Type": "application/json"},
            json_body={"username": self.s.api_user,
                       "password": self.s.api_password},
            timeout=self.s.timeout)
        if status != 200 or not isinstance(body, dict) or body.get("code") != 0:
            raise ApiError(f"平台登录失败（HTTP {status}）：{_msg(body)}",
                           status, body)
        self._token = (body.get("data") or {}).get("token") or ""
        if not self._token:
            raise ApiError("平台登录响应缺少 token", status, body)
        self._login_at = time.time()
        return self._token

    def token(self) -> str:
        if not self._token:
            self.login()
        return self._token

    # ---- 调用 ----
    def call(self, method: str, path: str, *, params: dict | None = None,
             body: dict | None = None, timeout: float | None = None) -> dict:
        """调用平台 API，返回 data 段（失败抛 ApiError）。"""
        # 只丢 None；保留空串——部分端点的空串有明确语义（如 AI 结论
        # 查询 status="" = 不限状态），全丢会让"查全部"变成"查待确认"
        params = {k: v for k, v in (params or {}).items() if v is not None}
        url = self.s.api_base + path
        t = timeout or self.s.timeout
        for attempt in (1, 2):
            headers = {"Authorization": "Bearer " + self.token()}
            if body is not None:
                headers["Content-Type"] = "application/json"
            status, payload = _http(method, url, headers=headers,
                                    params=params or None, json_body=body,
                                    timeout=t)
            if status == 401 and attempt == 1:
                self._token = ""            # token 过期/失效 → 重登一次
                continue
            if status >= 400:
                raise ApiError(f"{method} {path} 失败（HTTP {status}）："
                               f"{_msg(payload)}", status, payload)
            if isinstance(payload, dict) and "code" in payload:
                if payload.get("code") != 0:
                    raise ApiError(f"{method} {path} 业务错误：{_msg(payload)}",
                                   status, payload)
                return payload.get("data") or {}
            return payload if isinstance(payload, dict) else {"_raw": payload}
        raise ApiError(f"{method} {path} 鉴权失败（重登后仍 401）")

    # ---- 审计归属（尽力而为，失败不影响主流程） ----
    def audit(self, tool: str, detail: dict) -> None:
        try:
            self.call("POST", "/api/mcp/audit",
                      body={"tool": tool, "detail": detail,
                            "operator": "mcp:" + self.s.agent_name})
        except Exception as exc:                  # noqa: BLE001
            logger.warning("MCP 审计写入失败（不影响操作结果）：%s", exc)
        logger.info("MCP_WRITE tool=%s agent=%s detail=%s", tool,
                    self.s.agent_name, json.dumps(detail, ensure_ascii=False))


def _msg(payload) -> str:
    if isinstance(payload, dict):
        return str(payload.get("message") or payload.get("detail")
                   or payload)[:300]
    return str(payload)[:300]


# ---- 全局单例（测试可注入） ----
_settings = Settings.from_env()
_client: ApiClient | None = None


def get_client() -> ApiClient:
    global _client
    if _client is None:
        _client = ApiClient(_settings)
    return _client


def configure(settings: Settings | None = None,
              client: ApiClient | None = None) -> None:
    """测试/嵌入场景注入配置与客户端。"""
    global _settings, _client
    if settings is not None:
        _settings = settings
    if client is not None:
        _client = client


def _safe(fn, *args, **kwargs):
    """子调用容错：单个数据源失败不影响整个工具返回。"""
    try:
        return fn(*args, **kwargs)
    except ApiError as exc:
        return {"_error": str(exc)}


# ══════════════════════════════════════════════════════════════════════
# 写操作守卫（红线：AI 只出建议，落策略必须人工确认）
# ══════════════════════════════════════════════════════════════════════


def _find_exact_entry(list_type: str, target: str, value: str) -> dict | None:
    """精确查找某条名单条目（平台列表接口无重复校验，写前自查）。

    keyword 是 LIKE 语义，需在结果里做等值判断，避免
    `.com` 命中 `evil.com` 这类误判。
    """
    try:
        d = get_client().call("GET", "/api/list",
                              params={"list_type": list_type,
                                      "keyword": value, "size": 200})
    except ApiError:
        return None
    want = value.strip().lower()
    for it in d.get("items") or []:
        if (str(it.get("value", "")).strip().lower() == want
                and it.get("list_type") == list_type
                and it.get("target") == target):
            return it
    return None


def _guard(tool: str, confirm: bool, action: dict) -> dict | None:
    """返回 None = 放行；返回 dict = 拒绝并回传待确认动作。

    ⚠️ 名单红线（用户 2026-10-13 明确要求）：白名单/黑名单是**直接影响
    业务的策略**，改错会导致业务系统访问中断。因此：
      1) 服务默认只读（DNSF_MCP_ALLOW_WRITE 默认 0）——新部署一律不能写；
      2) 即便开启写能力，也必须调用方带 confirm=true（即用户已明确同意）；
      3) 禁止任何"AI 自主决定"的名单变更——AI 只出建议与证据。
    """
    if not _settings.allow_write:
        return {"ok": False, "rejected": "write_disabled",
                "message": "本 MCP 服务运行在**只读模式**（默认），拒绝一切写操作。"
                           "名单变更属高危操作（改错会中断业务访问），"
                           "请在管理端页面人工操作；确需让 Agent 代改时，"
                           "由管理员显式设置 DNSF_MCP_ALLOW_WRITE=1 并重启服务，"
                           "用完立即改回。",
                "pending_action": action,
                "tool": tool,
                "how_to_read_only_doc": "docs/…MCP 服务方案 V1.0.md §6 安全边界"}
    if not confirm:
        return {"ok": False, "rejected": "needs_confirmation",
                "message": "写操作需要**用户逐条明确同意**：请先向用户说明将要"
                           "执行的改动（改哪个名单、改哪条、影响面），"
                           "得到明确同意后再以 confirm=true 重新调用。"
                           "未经用户同意的名单变更属违规操作。",
                "pending_action": action,
                "tool": tool}
    return None


def _written(tool: str, result, detail: dict) -> dict:
    get_client().audit(tool, detail)
    return {"ok": True, "tool": tool, "result": result, "detail": detail,
            "note": _list_cache_hint}


# ══════════════════════════════════════════════════════════════════════
# 内网 DNS 解析链路拓扑（供 Agent 排障时判断"拦截发生在哪一层"）
# ══════════════════════════════════════════════════════════════════════

# 2026-10-23 由用户口述 + 对各节点原始 DNS 报文实测确认。
# 用途：domain_verdict / logs_query 只能看到本平台（.191）这一层的判定，
# 但客户端实际访问链路有 5 跳。排查"某域名访问不通"时，必须先定位
# 断点在哪一跳，否则会在错误的产品上反复加白。
#
#   客户端
#     └─> 域控 DNS  172.16.0.8 / 172.16.0.3（双机）
#           ├─ nimble.cn 本地域        → AD 本地解析
#           ├─ 条件转发器（白名单域）   → 172.16.7.2（白名单服务器，隔离网段）
#           └─ 常规外部域（DNS 转发器） → 172.16.7.1
#                 ├─ .7.1 自有公网域名封禁表命中 → 封禁（NXDOMAIN）
#                 └─ 未封禁                   → 转发 172.16.0.192
#                       └─ Go 代理 .192：注入 EDNS0 ECS（客户端真实 IP）
#                             └─ 172.16.0.191  ← 本 MCP 对应的平台
#                                   └─ 上游 223.5.5.5
#
# 已知两个与本平台无关、但会导致"域名访问不通"的外部断点（2026-10-23 实测）：
#   ① .7.1 对"顶级域自身无 A 记录、只靠 CNAME 挂 CDN"的域名返回 NXDOMAIN，
#      例如 ves.io / crates.io / golang.io / rust-lang.io / npmjs.io /
#      readthedocs.io / intercom.io / sentry.io / segment.io / branch.io。
#      自身带 A 记录的 github.io / pypi.org / docker.io / go.dev 正常。
#      连带影响：Go / Rust / Python 开发工具链不可达。
#      注意：UUID 风格的 CNAME 标签（如 ves-io-8034cc52-…-7ba79c6d0bde）
#      极易被 DGA / 熵值检测误判，是 .7.1 侧优先排查项。
#   ② .7.2 白名单服务器仅对域控条件转发器命中的域生效；.7.1 这层没有
#      对应的放行机制，两套名单各自为政。
#
# 排查口诀（避免误判）：
#   - 本平台拦截 → 有日志 + 返回 alert_ip 127.0.0.1
#   - .7.1 拦截 → 无本平台日志 + 返回 NXDOMAIN（且 .7.1 上有独立封禁表）
#   - 平台加白只能解决"名单误收录"（如 hagezi_ult 收录了正常商业域），
#     解决不了 .7.1 的 CNAME 缺陷——别在这类问题上反复加白。

_TOPOLOGY_CONTEXT = """
【内网 DNS 解析链路拓扑（2026-10-23 用户确认 + 实测）】
客户端 → 域控 172.16.0.8 / .3
  ├ nimble.cn 本地域 → AD 本地解析
  ├ 条件转发器(白名单域) → 172.16.7.2（白名单服务器）
  └ 常规外部域 → 转发器 → 172.16.7.1
      ├ .7.1 自有公网域名封禁表命中 → NXDOMAIN
      └ 未封禁 → 172.16.0.192（Go 代理，注入 ECS）
          └ 172.16.0.191 ← 本平台 → 上游 223.5.5.5

排障要点：
- 本平台拦截的标志 = 有 logs 记录 + 返回 127.0.0.1
- .7.1 拦截的标志 = 无本平台日志 + NXDOMAIN（.7.1 有独立封禁表，
  响应形式与本平台的 127.0.0.1 不同，别混淆）
- .7.1 对"顶级域无 A 记录、只靠 CNAME 挂 CDN"的域一律 NXDOMAIN
  （ves.io/crates.io/golang.io/npmjs.io/rust-lang.io/readthedocs.io 等，
  会导致 Go/Rust/Python 工具链不可达）。这属外部问题，平台加白无效。
- 判断"域名是否被拦"以 domain_verdict 为准；判断"访问是否通"要同时
  核对 CNAME 链每一跳（用原始 DNS 报文看 rcode/ancount，nslookup 的
  文字输出会把 NOERROR+空 answer 显示成空白，易误判）。
""".strip()

# 用户约定（2026-10-23 16:19）：每轮回答末尾附一段"引导式 MCP 能力提示"，
# 让用户知道接下来可以怎么问、AI 能用哪些工具继续深入。这样用户不需要
# 背工具名，看到提示就能自然地提出下一步。
_RESPONSE_GUIDE = """
【回答末尾必做（用户约定，必须遵守）】
每轮回答的末尾，附一段简短的"接下来你可以这样问"引导提示（2~4 行，
选与当前话题最相关的 1~2 项，不要罗列全部——保持轻量，不喧宾夺主）。
格式建议：

💡 接下来你可以这样问：
- "<结合当前话题的具体问法，如：把 xxx.com 加白，备注写 yyy>"

素材按场景选：
- 拦截/域名话题 → "这个域名为什么被拦 / 帮我看看 xxx.com 可疑吗"
  （domain_verdict / domain_investigate）
- 误报治理 → "最近有哪些误报该加白的"（ai_findings false_positive）
- 趋势/态势 → "今天拦截情况怎么样 / 最近24小时哪个时段拦截最多"
  （system_status / traffic_stats）
- 名单操作 → "把 xxx.com 加白，备注写 <说明>"（需开写能力+逐条确认）
- 威胁排查 → "有没有 DNS 隧道 / DGA / 失陷主机的迹象"（ai_findings）
""".strip()


# ══════════════════════════════════════════════════════════════════════
# MCP 服务器与工具
# ══════════════════════════════════════════════════════════════════════

from mcp.server.mcpserver import MCPServer            # noqa: E402

server = MCPServer(
    name=SERVER_NAME,
    version=SERVER_VERSION,
    instructions=(
        "企业 DNS 安全过滤中间件的操作接口。系统在 DNS 解析链路上做五层"
        "检测：L1 本地黑白名单 → L2 离线大名单（600 万条，hagezi/银狐等"
        "十源）→ L3 新注册域名（NRD/RDAP）→ L4 在线情报源 → L5 IP 后置"
        "过滤；命中即返回告警应答（alert_ip 127.0.0.1）。\n\n"
        "推荐用法：\n"
        "1) 先 system_status 看整体，再 domain_verdict 判单域名的处置结果；\n"
        "2) 想知道『这域名为什么可疑/是不是误伤』用 domain_investigate"
        "（含首现时间、注册时间、AI 结论、拦截史）；\n"
        "3) 误伤治理流程：ai_findings(finding_type='false_positive') 拿清单"
        "→ 向用户确认 → false_positive_whitelist(confirm=true) 加白；\n"
        "4) 未知威胁：ai_findings(finding_type='dga_suspect'/'tunnel_suspect')"
        "、ai_findings(finding_type='threat_cluster') 看族群。\n\n"
        + _TOPOLOGY_CONTEXT + "\n\n"
        + _RESPONSE_GUIDE + "\n\n"
        "红线（必须遵守）：\n"
        "- **白名单/黑名单是直接影响业务的策略，改错会中断业务系统访问**。"
        "绝不允许 AI 自主决定任何名单变更：只有用户在当前对话中【逐条明确"
        "要求】时，才可带 confirm=true 调用写工具；用户未点名具体条目时，"
        "一律只输出建议与证据，让用户在管理端页面自行操作。\n"
        "- 服务默认只读（DNSF_MCP_ALLOW_WRITE 默认 0）。只读模式下所有写工具"
        "返回 write_disabled，这是预期行为，不要重试或绕过。\n"
        "- 改动前先跑 list_query 把「要改哪条、当前值、影响面」报给用户确认。\n"
        "- 名单改动生效需 ≤60s（缓存重载），验证拦截请稍候再查。\n"
        "- 排障时先判断断点在哪一跳：见上方【内网 DNS 解析链路拓扑】。"
        "对外部断点（.7.1 封禁、CNAME 缺陷）不要在本平台反复加白。\n"
        "- 回答末尾按【回答末尾必做】附引导式提示——这是用户的明确约定。"
    ),
)


def _errors(fn):
    """统一错误面：API 异常转为结构化错误返回（而非协议级异常）。

    这样 Agent 拿到的是可读的 {ok: false, error, status}，能自行决定
    重试/换参/上报，而不是一个 MCP 调用失败。functools.wraps 保留
    签名与文档——SDK 据此生成工具 JSON Schema。
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ApiError as exc:
            return {"ok": False, "error": str(exc), "status": exc.status,
                    "payload": exc.payload if isinstance(exc.payload, dict)
                    else None,
                    "hint": "平台 API 调用失败：请检查参数或先用只读工具确认对象存在"}
    return wrapper


# ------ 只读工具 ------------------------------------------------------


@server.tool()
@_errors
def system_status() -> dict:
    """平台整体状态：今日流量与拦截率、检测开关、五层拦截分布、AI 结论
    规模、情报源启用情况、队列与熔断状态。『现在什么情况』先调这个。

    返回：traffic(今日总量/拦截/放行/拦截率)、detection_enabled、
    layers(五层计数与启用态)、ai(首现表规模/待确认结论数)、
    sources(离线源/在线源启用数)、health(队列积压/熔断)。
    """
    c = get_client()
    st = _safe(c.call, "GET", "/api/status")
    layers = _safe(c.call, "GET", "/api/status/layers",
                   params={"scope": "today"})
    ai = _safe(c.call, "GET", "/api/ai/stats")
    q = _safe(c.call, "GET", "/api/queue-stats")
    sources = _safe(c.call, "GET", "/api/threatintel")
    tl = _safe(c.call, "GET", "/api/threatlist/sources")

    total = st.get("today_total") or 0
    inter = st.get("today_intercepts") or 0
    out = {
        "detection_enabled": st.get("detection_enabled"),
        "traffic": {
            "today_total": total,
            "today_intercepts": inter,
            "today_removes": st.get("today_removes"),
            "today_allows": st.get("today_allows"),
            "intercept_rate_pct": round(100.0 * inter / total, 2)
            if total else None,
            "stats_source": st.get("stats_source"),
        },
        "layers": [
            {"key": ly.get("key"), "label": ly.get("label"),
             "count": ly.get("count"), "active": ly.get("active")}
            for ly in (layers.get("layers") or [])
        ] if isinstance(layers, dict) else layers,
        "ai": {
            "first_seen_total": ai.get("first_seen_total"),
            "first_seen_24h": ai.get("first_seen_24h"),
            "pending_findings": ai.get("findings"),
        },
        "sources": {
            "offline_enabled": sum(
                1 for s in (tl.get("items") or []) if s.get("enabled")),
            "offline_total": len(tl.get("items") or []),
            "online_enabled": sum(
                1 for s in (sources.get("items") or []) if s.get("enabled")),
            "online_total": len(sources.get("items") or []),
        },
        "health": q,
    }
    return out


@server.tool()
@_errors
def domain_verdict(domain: str, query_type: str = "A") -> dict:
    """判定某域名/PTR 在本系统的**实际处置结果**（拦截还是放行、命中了
    哪一层的哪条规则）。

    - query_type：A / AAAA / PTR（PTR 时 domain 传 IP 字符串）；
    - 白名单优先级最高，其次本地黑名单、离线大名单、NRD、在线情报；
    - 返回 final_verdict.action = allow / intercept 与 reason（含命中来源），
      以及各层逐项命中明细。

    用途：回答『xxx.com 会被拦吗/为什么被拦』。判断域名是否被拦，请以此
    工具为准，不要凭名单搜索结果猜。
    """
    domain = (domain or "").strip()
    if not domain:
        return {"error": "domain 不能为空"}
    return get_client().call("POST", "/api/test/domain",
                             body={"domain": domain,
                                   "query_type": (query_type or "A").upper()})


@server.tool()
@_errors
def domain_investigate(domain: str, log_limit: int = 20) -> dict:
    """域名综合画像（排查『这域名为什么可疑 / 是不是误伤』的首选）。

    一次性汇总：① 当前处置结果与命中规则（domain_verdict）；② 首现时间、
    注册时间、AI 结论（DGA/隧道/误报/行为）与证据；③ 白名单/黑名单条目；
    ④ 最近拦截日志；⑤ 自然语言研判摘要（未配置 LLM 时为结构化摘要）。

    返回：verdict、facts（首现/注册/AI 结论）、summary、list_entries、
    recent_logs。
    """
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return {"error": "domain 不能为空"}
    c = get_client()
    out = {"domain": domain}
    out["verdict"] = _safe(c.call, "POST", "/api/test/domain",
                           body={"domain": domain, "query_type": "A"})
    summary = _safe(c.call, "POST", "/api/ai/llm/summarize",
                    params={"domain": domain})
    out["facts"] = summary.get("facts") if isinstance(summary, dict) else None
    out["summary"] = summary.get("content") if isinstance(summary, dict) else None
    out["summary_source"] = (summary.get("source")
                             if isinstance(summary, dict) else None)
    out["list_entries"] = _safe(
        c.call, "GET", "/api/list",
        params={"keyword": domain, "size": 50}).get("items", [])
    out["recent_logs"] = _safe(
        c.call, "GET", "/api/logs",
        params={"domain": domain, "size": max(1, min(log_limit, 200))}
    ).get("items", [])
    return out


@server.tool()
@_errors
def list_query(list_type: str = "", keyword: str = "", page: int = 1,
               size: int = 50) -> dict:
    """查询黑白名单条目（含条目 id，供后续停用/删除/修正）。

    - list_type：blacklist / whitelist，留空则两类都查；
    - keyword：按 value 模糊匹配（域名或 IP 片段）；
    - 每条返回 level（tld/registrable/subdomain）、wildcard、risk 风险标注。
    """
    return get_client().call(
        "GET", "/api/list",
        params={"list_type": list_type, "keyword": keyword,
                "page": max(1, page), "size": max(1, min(size, 200))})


@server.tool()
@_errors
def ai_findings(finding_type: str = "", status: str = "pending",
                min_score: float = 0.0, limit: int = 50) -> dict:
    """查询 AI 分析结论（带评分与可解释证据）。

    finding_type 取值（留空=全部）：
      dga_suspect    疑似 DGA 自动生成域名（含 bigram/熵/数字比等证据）
      tunnel_suspect 疑似 DNS 隧道/外泄会话（客户端|父域，含查询数/熵）
      false_positive 疑似误报（建议加白，证据含多客户端共访等）
      threat_cluster 威胁族群（攻击基础设施聚类，含命中源分布）
      client_anomaly 异常客户端（疑似失陷主机）
      intel_quality  情报源质量评分

    status：pending（待人工确认）/confirmed/dismissed/留空=全部。
    min_score：最低评分（0~1）。默认只返回待确认的列表。
    """
    return get_client().call(
        "GET", "/api/ai/findings",
        params={"type": finding_type, "status": status,
                "min_score": min_score if min_score else None,
                "limit": max(1, min(limit, 500))})


@server.tool()
@_errors
def traffic_stats(hours: int = 24) -> dict:
    """流量与拦截统计：今日总览 + 按小时拦截趋势 + 五层分布。

    hours：小时趋势的窗口（1~168）。趋势里含各层每小时拦截量
    （local_blacklist/threat_list/nrd/threatintel/ip_filter），
    可回答『哪个时段哪一层在挨打』。
    """
    c = get_client()
    return {
        "today": _safe(c.call, "GET", "/api/status"),
        "hourly": _safe(c.call, "GET", "/api/status/hourly",
                        params={"hours": max(1, min(hours, 168))}),
        "layers": _safe(c.call, "GET", "/api/status/layers",
                        params={"scope": "today"}),
    }


@server.tool()
@_errors
def logs_query(domain: str = "", client_ip: str = "", action: str = "",
               reason: str = "", start: str = "", end: str = "",
               size: int = 50) -> dict:
    """查询过滤日志（仅记录拦截/白名单放行/观察；普通放行只计数）。

    - domain / client_ip：按域名或客户端 IP 精确筛选；
    - action：intercept / remove_ip / allow / observe；
    - reason：filter_reason 片段，如 threat_list:silverfox、local_blacklist、
      nrd、threatintel:zen、ip_filter；
    - start / end：时间范围，格式 'YYYY-MM-DD HH:MM:SS'。

    注意：日志为异步批量落库（秒级延迟）；要确认某域名此刻的真实处置，
    请用 domain_verdict 而非日志。
    """
    return get_client().call(
        "GET", "/api/logs",
        params={"domain": domain, "client_ip": client_ip, "action": action,
                "reason": reason, "start": start, "end": end,
                "size": max(1, min(size, 200))})


@server.tool()
@_errors
def intel_sources() -> dict:
    """情报源清单与质量评估。

    返回 offline（内置离线大名单：启用态、条目数）、online（在线情报源
    适配器：启用态、最近可用性）、quality（AI 评分：命中贡献与命中密度，
    用于识别『条目多却从不命中』的失效源）。
    """
    c = get_client()
    return {
        "offline": _safe(c.call, "GET", "/api/threatlist/sources"),
        "online": _safe(c.call, "GET", "/api/threatintel"),
        "quality": _safe(c.call, "GET", "/api/ai/intel-quality"),
    }


@server.tool()
@_errors
def ai_report() -> dict:
    """生成 AI 安全研判日报（趋势 + 待办 + 处置建议）。

    配置了 LLM 时返回自然语言报告（source='llm'）；未配置或调用失败时
    自动降级为结构化报告（source='structured'），功能始终可用。
    返回：source、content（markdown/纯文本）。
    """
    return get_client().call("POST", "/api/ai/llm/report")


@server.tool()
@_errors
def ai_ask(question: str) -> dict:
    """用自然语言提问（以当前 AI 结论为事实上下文，不编造）。

    适合『有哪些域名建议加白？』『今天最该关注什么？』这类问句。
    未配置 LLM 时返回结论概览（source='structured'）。
    """
    question = (question or "").strip()
    if not question:
        return {"error": "question 不能为空"}
    return get_client().call("POST", "/api/ai/llm/ask",
                             params={"question": question})


# ── 写工具（需 confirm=true，且先取得用户同意） ──────────────────────


@server.tool()
@_errors
def whitelist_add(value: str, target: str = "domain", remark: str = "",
                  confirm: bool = False) -> dict:
    """【写·高危】加白名单（该域名/IP 直接放行，优先于所有检测层）。

    ⚠️ 高危：名单变更直接影响业务访问，**只在用户当前对话中逐条明确要求时**调用；
    禁止因『分析结论』或『我认为该加白』而自主调用。

    调用前必须已获得用户明确同意；首次调用建议 confirm=false 以获取
    待确认动作回执，向用户复述后再 confirm=true 执行。

    - value：域名（支持 *.example.com 通配）或 IP；
    - target：domain / ip；
    - remark：备注（建议写明原因与来源，便于日后审计）。
    """
    action = {"action": "whitelist_add", "target": target, "value": value,
              "remark": remark}
    deny = _guard("whitelist_add", confirm, action)
    if deny:
        return deny
    exist = _find_exact_entry("whitelist", target, value)
    if exist:
        return {"ok": True, "already_present": True, "existing": exist,
                "message": f"{value} 已在白名单中（id={exist.get('id')}，"
                           f"启用={bool(exist.get('enabled'))}），未重复添加。"
                           "若需覆盖备注或改为启用，请用 list_entry_set_enabled。"}
    res = get_client().call("POST", "/api/list",
                            body={"list_type": "whitelist", "target": target,
                                  "value": value, "enabled": True,
                                  "remark": remark or "MCP 加白"})
    return _written("whitelist_add", res, action)


@server.tool()
@_errors
def blacklist_add(value: str, target: str = "domain", remark: str = "",
                  confirm: bool = False) -> dict:
    """【写·高危】加黑名单（命中即拦截，返回告警应答 alert_ip）。

    ⚠️ 高危：名单变更直接影响业务访问，**只在用户当前对话中逐条明确要求时**调用；
    禁止因『分析结论』或『我认为该加白』而自主调用。

    调用前必须已获得用户明确同意。注意：`*.com`、`*.jp` 这类**顶层通配**
    会影响整片互联网，切勿使用；如确需整域管控，请先向用户说明影响面。

    - value：域名（支持 *.example.com）或 IP；target：domain / ip。
    """
    action = {"action": "blacklist_add", "target": target, "value": value,
              "remark": remark}
    deny = _guard("blacklist_add", confirm, action)
    if deny:
        return deny
    exist = _find_exact_entry("blacklist", target, value)
    if exist:
        return {"ok": True, "already_present": True, "existing": exist,
                "message": f"{value} 已在黑名单中（id={exist.get('id')}，"
                           f"启用={bool(exist.get('enabled'))}），未重复添加。"}
    res = get_client().call("POST", "/api/list",
                            body={"list_type": "blacklist", "target": target,
                                  "value": value, "enabled": True,
                                  "remark": remark or "MCP 加黑"})
    return _written("blacklist_add", res, action)


@server.tool()
@_errors
def list_entry_set_enabled(item_id: int, enabled: bool,
                           confirm: bool = False) -> dict:
    """【写·高危】启用/停用一条名单条目（停用 = 保留条目但不生效，可逆）。

    ⚠️ 高危：名单变更直接影响业务访问，**只在用户当前对话中逐条明确要求时**调用；
    禁止因『分析结论』或『我认为该加白』而自主调用。

    调用前必须已获得用户明确同意。item_id 可由 list_query 获得。
    """
    action = {"action": "list_entry_set_enabled", "id": item_id,
              "enabled": enabled}
    deny = _guard("list_entry_set_enabled", confirm, action)
    if deny:
        return deny
    res = get_client().call("PUT", f"/api/list/{int(item_id)}",
                            body={"enabled": bool(enabled)})
    return _written("list_entry_set_enabled", res, action)


@server.tool()
@_errors
def list_entry_delete(item_id: int, confirm: bool = False) -> dict:
    """【写·高危】删除一条名单条目（不可恢复，建议优先用停用）。

    ⚠️ 高危：名单变更直接影响业务访问，**只在用户当前对话中逐条明确要求时**调用；
    禁止因『分析结论』或『我认为该加白』而自主调用。

    调用前必须已获得用户明确同意；删除前请先用 list_query 向用户展示
    该条目的 value/remark，确认删的是正确条目。
    """
    action = {"action": "list_entry_delete", "id": item_id}
    deny = _guard("list_entry_delete", confirm, action)
    if deny:
        return deny
    res = get_client().call("DELETE", f"/api/list/{int(item_id)}")
    return _written("list_entry_delete", res, action)


@server.tool()
@_errors
def finding_decide(finding_id: int, status: str, confirm: bool = False) -> dict:
    """【写】对 AI 结论做人工决断：confirmed（确认）或 dismissed（忽略）。

    此操作**不改变任何拦截策略**（只记录人的判断），但仍需用户明确同意。

    仅记录人的判断（会保留、不被快照清理），**不改变任何拦截策略**。
    调用前必须已获得用户明确同意。finding_id 来自 ai_findings。
    """
    status = (status or "").strip().lower()
    if status not in ("confirmed", "dismissed"):
        return {"error": "status 仅支持 confirmed / dismissed"}
    action = {"action": "finding_decide", "id": finding_id, "status": status}
    deny = _guard("finding_decide", confirm, action)
    if deny:
        return deny
    res = get_client().call("POST",
                            f"/api/ai/findings/{int(finding_id)}/status",
                            params={"status": status})
    return _written("finding_decide", res, action)


@server.tool()
@_errors
def false_positive_whitelist(domain: str, remark: str = "",
                             confirm: bool = False) -> dict:
    """【写·高危】把 AI 判定的疑似误伤域名一键加白（同时把该结论标记为已确认）。

    ⚠️ 高危：名单变更直接影响业务访问，**只在用户当前对话中逐条明确要求时**调用；
    禁止因『分析结论』或『我认为该加白』而自主调用。

    误伤治理闭环的最后一步：ai_findings(finding_type='false_positive')
    拿到清单 → 向用户确认 → 本工具执行。调用前必须已获得用户明确同意。

    - domain：要加白的域名（不含通配符；如需通配请用 whitelist_add）。
    """
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return {"error": "domain 不能为空"}
    action = {"action": "false_positive_whitelist", "domain": domain,
              "remark": remark}
    deny = _guard("false_positive_whitelist", confirm, action)
    if deny:
        return deny
    res = get_client().call("POST",
                            f"/api/ai/false-positive/{domain}/whitelist",
                            params={"remark": remark or "MCP 误伤加白"})
    return _written("false_positive_whitelist", res, action)


# ── 提示词模板（引导 Agent 按 SOP 作业） ─────────────────────────────


@server.prompt()
def investigate_domain(domain: str) -> str:
    """按 SOP 调查一个域名：处置结果 → 为什么 → 是否误伤 → 处置建议。"""
    return (
        f"请调查域名 {domain} 在企业 DNS 安全过滤系统中的情况，步骤：\n"
        f"1) 调 domain_investigate(domain='{domain}') 拿全景（处置结果 + "
        f"首现/注册时间 + AI 结论 + 拦截史）；\n"
        "2) 若命中拦截，指出命中层级与规则来源，并解释威胁性质；\n"
        "3) 判断是否存在误伤迹象（多客户端共访、老域名、业务特征、"
        "AI 误报评分），给出明确倾向：保留拦截 / 建议加白；\n"
        "4) 若建议加白，先说明理由与影响面并征得我同意，再执行写操作；\n"
        "5) 最后给出一段不超过 200 字的结论（结论先行）。"
    )


@server.prompt()
def daily_briefing() -> str:
    """生成每日安全简报：态势 + 待办 + 建议动作。"""
    return (
        "请生成今日 DNS 安全简报，步骤：\n"
        "1) system_status 看整体态势与健康；\n"
        "2) ai_report 拿 AI 研判；\n"
        "3) ai_findings(finding_type='false_positive') 与 "
        "ai_findings(finding_type='threat_cluster') 看待办与威胁族群；\n"
        "4) 输出：① 一句话态势；② 今日最该关注的 3 件事（按优先级）；"
        "③ 需要我拍板的动作清单（加白/加黑/确认结论），每项附理由。"
    )


# ══════════════════════════════════════════════════════════════════════
# 传输层
# ══════════════════════════════════════════════════════════════════════


class BearerAuthMiddleware:
    """纯 ASGI 中间件：校验 Authorization: Bearer <token>。

    用纯 ASGI 而非 BaseHTTPMiddleware——后者会缓冲响应体，破坏
    streamable-http 的流式语义。
    """

    def __init__(self, app, token: str):
        self.app = app
        self.token = token

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or not self.token:
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers") or []}
        if headers.get("authorization", "") != "Bearer " + self.token:
            body = b'{"error":"unauthorized","hint":"need Bearer token"}'
            await send({"type": "http.response.start", "status": 401,
                        "headers": [(b"content-type", "application/json"),
                                    (b"content-length",
                                     str(len(body)).encode())]})
            await send({"type": "http.response.body", "body": body})
            return
        return await self.app(scope, receive, send)


def _local_ipv4() -> list[str]:
    """本机 IPv4（用于 Host 校验白名单）。取不到就返回空列表。"""
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ":" not in ip:
                ips.add(ip)
    except OSError:
        pass
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("223.5.5.5", 80))
            ips.add(probe.getsockname()[0])
        finally:
            probe.close()
    except OSError:
        pass
    return sorted(ips)


def _transport_security(settings: "Settings"):
    """Host/Origin 白名单（SDK 的 DNS rebinding 防护）。

    生产实测教训：用 0.0.0.0 绑定但不放行本机网卡 IP 时，远端 Agent 按
    `http://<内网IP>:8090/mcp` 访问会被 SDK 直接拒（Host 校验不过）。
    这里把回环 + 各网卡 IP 都放行；Bearer Token 仍是主防线，本项为纵深防御。
    """
    from mcp.server.transport_security import TransportSecuritySettings

    hosts = {"127.0.0.1:*", "localhost:*", "[::1]:*"}
    if settings.host and settings.host not in ("0.0.0.0", "::"):
        hosts.add(f"{settings.host}:*")
    for ip in _local_ipv4():
        hosts.add(f"{ip}:*")
    allowed = sorted(hosts)
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed,
        allowed_origins=[f"http://{h}" for h in allowed]
                        + [f"https://{h}" for h in allowed],
    )


def build_http_app(settings: "Settings"):
    """构造 streamable-http 应用（含 Bearer 鉴权中间件）。

    单独抽出来是为了**可测**：生产曾因给 streamable_http_app() 传了它
    不接受的 port 参数而启动即崩（服务反复重启），构造路径必须有测试覆盖。
    """
    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        transport_security=_transport_security(settings))
    app.add_middleware(BearerAuthMiddleware, token=settings.token)
    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="DNS 安全过滤中间件 MCP 服务")
    parser.add_argument("--transport", choices=("stdio", "http"),
                        default=None, help="传输方式（默认取环境变量/stdio）")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr)

    s = Settings.from_env()
    if args.transport:
        s.transport = args.transport
    if args.host:
        s.host = args.host
    if args.port:
        s.port = args.port
    configure(s)

    if not s.api_password:
        logger.error("缺少 DNSF_API_PASSWORD（平台账号密码），无法启动")
        return 2

    if s.transport == "stdio":
        logger.info("MCP stdio 启动（平台 %s，写能力 %s）", s.api_base,
                    "开" if s.allow_write else "只读")
        server.run("stdio")
        return 0

    # streamable-http（远端 Agent）
    if not s.token:
        logger.error("http 传输必须设置 DNSF_MCP_TOKEN（Bearer 鉴权），拒绝裸奔启动")
        return 2
    import uvicorn

    app = build_http_app(s)
    logger.info("MCP streamable-http 启动：http://%s:%s/mcp（写能力 %s）",
                s.host, s.port, "开" if s.allow_write else "只读")
    uvicorn.run(app, host=s.host, port=s.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
