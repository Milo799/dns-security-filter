# Windows DNS 安全过滤中间件 · MCP 服务方案

> 版本 V1.0 ｜ 2026-10-13 ｜ 迭代 50 ｜ 实现：`platform/mcp_server.py` + `app/routers/mcp.py` + `deploy/install-mcp.sh`

---

## 1. 定位：把系统变成「Agent 可操作的对象」

大屏解决的是「人看」，MCP 解决的是「Agent 用」。两者的差别不是形态，而是**谁在消费这个系统**：

| | 大屏（已交付 screen/screen2/screen3） | MCP 服务（本方案） |
|---|---|---|
| 消费者 | 值班人眼 | AI Agent（WorkBuddy / Claude / IDE Copilot / 自研） |
| 交互 | 看板 + 人工点击 | 自然语言 → 工具调用 → 结构化结果 |
| 典型问题 | 「今天怎么样」 | 「github.com 会被拦吗，为什么，要不要加白」 |
| 价值 | 态势感知 | **让 Agent 直接作业，不必人肉转述** |

一句话判断：**只读的能力已经散落在 60+ 个 REST 端点上，Agent 无法自己发现与编排——MCP 就是把这些能力收敛成一份带语义契约的工具面。**

---

## 2. 能力面：16 个工具

### 2.1 只读工具（10 个，自由调用）

| 工具 | 回答的问题 | 关键参数 |
|---|---|---|
| `system_status` | 现在整体什么情况（流量/拦截率/五层分布/AI 规模/源启用/健康） | — |
| `domain_verdict` | **这域名会被拦还是放行？命中了哪层哪条规则？** | `domain`, `query_type`(A/AAAA/PTR) |
| `domain_investigate` | 这域名为什么可疑 / 是不是误伤（首现+注册+AI 结论+名单+拦截史+摘要） | `domain`, `log_limit` |
| `list_query` | 黑白名单里有什么（含条目 id、层级、通配、风险标注） | `list_type`, `keyword`, `page`, `size` |
| `ai_findings` | AI 结论清单（DGA/隧道/误报/族群/异常客户端/情报质量） | `finding_type`, `status`, `min_score`, `limit` |
| `traffic_stats` | 流量与拦截趋势（按小时、按层） | `hours` |
| `logs_query` | 过滤日志（谁、什么域名、什么原因被处置） | `domain`, `client_ip`, `action`, `reason`, `start`, `end` |
| `intel_sources` | 情报源清单与质量（谁能干活、谁在空转） | — |
| `ai_report` | 生成 AI 研判日报（未配 LLM 自动结构化降级） | — |
| `ai_ask` | 用自然语言提问（以 AI 结论为事实上下文） | `question` |

### 2.2 写工具（6 个，均需 `confirm=true`）

| 工具 | 作用 | 备注 |
|---|---|---|
| `whitelist_add` | 加白（优先于所有检测层） | 写前查重，重复调用幂等返回 `already_present` |
| `blacklist_add` | 加黑（命中即拦截） | 顶层通配 `*.com` 会提示影响面 |
| `list_entry_set_enabled` | 启用/停用某条名单条目 | 可逆，优先于删除 |
| `list_entry_delete` | 删除名单条目 | 不可恢复 |
| `finding_decide` | 确认/忽略 AI 结论 | **只记录人的判断，不改策略** |
| `false_positive_whitelist` | 误伤加白（同时把结论标记 confirmed） | 误伤治理闭环的最后一环 |

### 2.3 提示词模板（2 个）

`investigate_domain(domain)`（按 SOP 调查域名：处置 → 原因 → 是否误伤 → 建议）
`daily_briefing()`（生成每日简报：态势 + 待办 + 需拍板动作）

---

## 3. 架构与红线

```
Agent ── stdio / streamable-http ──▶ mcp_server.py
                                        │  10 只读 + 6 写
                                        ▼
                            platform Web API（/api/*，Bearer）
                                        │
                                        ▼
                       SQLite（策略/日志/结论）＋ DNS 进程（15353）
```

**🚨 第 0 条红线（用户 2026-10-13 明确要求）：名单只能由人改**

> **白名单/黑名单是直接影响业务访问的策略——改错会导致业务系统访问中断。**
> 因此：① 服务**默认只读**（`DNSF_MCP_ALLOW_WRITE` 默认 0），新部署一律不能写；
> ② 即便显式开启写能力，也**必须用户在当前对话中逐条点名要求**才可执行，
> 禁止任何"AI 自己判断该加白/加黑"的动作；③ AI 侧只输出**建议 + 证据 + 影响面**，
> 由人在管理端页面操作；④ 所有写操作双重审计留痕。

**四条硬约束（写进代码，不是口号）：**

1. **不直连数据库**：所有读写都经平台 Web API——复用既有鉴权、参数校验、`invalidate_list_cache()` 缓存失效、审计留痕。新增旁路写入口是安全大忌。
2. **写操作三重闸门**：
   - 进程开关 `DNSF_MCP_ALLOW_WRITE`（**默认 0 = 只读**，写工具一律返回 `write_disabled`；
     要开启须显式传 `--allow-write` 或改环境变量后重启，用完立刻改回）
   - 调用方 `confirm=true`（缺省返回 `needs_confirmation` + `pending_action`，供 Agent 向用户复述）
   - 平台侧审计（`audit_log` 同时留两条：API 业务审计 + `mcp_<工具>` 归属审计）
3. **AI 只出建议**：MCP 不提供「自动加白」「自动拦截」——`false_positive_whitelist` 也必须带 `confirm=true`，语义是「人已确认，Agent 代按」。
4. **生产零依赖**：MCP 挂了只影响 Agent 操作，DNS 解析与检测链路完全不受影响（它是旁路进程）。

---

## 4. 部署

```bash
# 机 B（检测平台）部署完平台之后
sudo ./deploy/install-mcp.sh                      # **默认只读**（名单变更请在管理端操作）
sudo ./deploy/install-mcp.sh --allow-write        # 显式开启写能力（仍需用户逐条确认）
sudo ./deploy/install-mcp.sh --pip-proxy http://172.16.5.7:3128   # 内网出站
```

脚本做 5 件事（幂等）：装 MCP SDK 到平台 venv → 生成 `/etc/dnsfilter/mcp.env`（600，含平台密码与随机 Bearer Token）→ 装 `dnsfilter-mcp.service` → 启动 → 自检（未授权必须 401、带 Token 必须能握手并列出 16 工具）。

**环境变量**（`/etc/dnsfilter/mcp.env`）：

| 变量 | 默认 | 说明 |
|---|---|---|
| `DNSF_API_BASE` | `http://127.0.0.1:8080` | 平台 Web 地址（同机用回环） |
| `DNSF_API_USER` / `DNSF_API_PASSWORD` | admin / — | 平台凭据（必填） |
| `DNSF_MCP_TRANSPORT` | stdio | `stdio` 或 `http` |
| `DNSF_MCP_HOST` / `DNSF_MCP_PORT` | 0.0.0.0 / 8090 | http 模式绑定 |
| `DNSF_MCP_TOKEN` | — | **http 模式必填**（缺失则拒绝启动，不裸奔） |
| `DNSF_MCP_ALLOW_WRITE` | **0（只读）** | 1 才开启写能力；名单变更属高危，默认关闭 |
| `DNSF_MCP_AGENT` | mcp-agent | 写入审计归属名 |

---

## 5. 接入方式

### 5.1 stdio（同机 / 本机 Agent，无需 Token）

```jsonc
{
  "mcpServers": {
    "dns-security-filter": {
      "type": "stdio",
      "command": "/opt/dns-security-filter/platform/venv/bin/python",
      "args": ["/opt/dns-security-filter/platform/mcp_server.py"],
      "env": {
        "DNSF_API_BASE": "http://127.0.0.1:8080",
        "DNSF_API_PASSWORD": "<平台密码>",
        "DNSF_MCP_AGENT": "my-agent",
        "DNSF_MCP_ALLOW_WRITE": "1"
      }
    }
  }
}
```

### 5.2 streamable-http（跨网段 / 多 Agent 共用）

```
URL    : http://<机B>:8090/mcp
Header : Authorization: Bearer <mcp.env 里的 DNSF_MCP_TOKEN>
```

HTTP 传输用纯 ASGI 中间件做 Bearer 校验（不用 `BaseHTTPMiddleware`——它会缓冲响应体、破坏流式语义）。未带 Token 一律 401。

---

### 5.3 日常怎么用（30 秒上手）

**路径 A：在本机 AI 客户端里用（最省事，不必记工具名）**

1. 打开 AI 客户端左下角加号菜单 → 连接器管理 → 找到 `dns-security-filter` → 点 **「信任」**
   （写在 `mcp.json` 里的自定义服务必须先信任，客户端才会去启动它）；
2. 之后**直接用自然语言提问**，Agent 自行选工具调用；
3. 写操作（加白/加黑）Agent 会先把待办动作复述给你、等你同意，才带 `confirm=true` 执行。

可直接照抄的问法：

| 你想知道 | 直接问 |
|---|---|
| 单域名的处置结果 | 「`xybpoxl.biz` 会不会被拦？命中哪条规则？」 |
| 为什么可疑 / 是否误伤 | 「调查一下 `xxxx.xyz`，是不是误伤，要不要加白」 |
| 整体态势 | 「DNS 现在什么情况？今天拦截率多少」 |
| 威胁面 | 「今天有哪些威胁族群？挑最严重的三个说说」 |
| 未知威胁 | 「有没有疑似 DGA 或 DNS 隧道的域名？」 |
| 误伤治理 | 「哪些域名建议加白？」→（确认后）「把 `github.com` 加白，备注：开发需要」 |
| 失陷主机 | 「有没有行为异常的客户端（疑似失陷）？」 |
| 情报源质量 | 「哪些情报源在空转？」 |
| 日志排查 | 「`10.6.6.6` 最近被拦了哪些域名？」 |
| 日报 | 「生成今天的 DNS 安全简报」 |

**路径 B：给其他 Agent / IDE / 自研程序用**

- 同机：按 §5.1 的 stdio 配置填 `command` / `args` / `env`（env 里给平台地址与口令即可，无需 Token）；
- 跨网段：按 §5.2 连 `http://<机B>:8090/mcp`，请求头带 `Authorization: Bearer <DNSF_MCP_TOKEN>`
  （Token 在 `/etc/dnsfilter/mcp.env`，600 权限）；
- 默认就是只读（`DNSF_MCP_ALLOW_WRITE=0`），所有写工具返回 `write_disabled`——
  **这是预期行为**：名单变更请你在管理端页面操作。确需让 Agent 代改时，管理员显式
  开启写能力（`--allow-write` 或改环境变量后重启），并在对话中**逐条点名**要改哪一条。

**三条使用注意**

1. **写操作有生效延迟**：名单写入 → 平台名单缓存 ≤60s 重载 → DNS 进程 cross_sync 60s 同步
   （写工具返回的 `note` 里也带了这句）。要复验拦截，等 60s 再 dig 或调 `domain_verdict`。
2. **判定以 `domain_verdict` 为准**：它把真实检测链路的规则跑一遍，比肉眼在名单里搜关键词可靠
   （名单查询是 LIKE 匹配，`.com` 会命中 `evil.com` 这类噪声）。
3. **写操作全程留痕**：`audit_log` 记两条——平台业务审计 + `mcp_<工具>`
   （operator='mcp:<agent名>'），管理端审计页显示中文标签（如「MCP 误伤加白」）。

## 6. 安全边界

| 面 | 措施 |
|---|---|
| 传输 | http 强制 Bearer Token；Token 随机 32 字节（`token_urlsafe`），存 600 权限文件 |
| 权限 | 等于平台 admin（能调用的 API 都能调）——**因此默认只读安装**，确需写入时临时开启 |
| 名单红线 | 默认只读；开启写能力后仍须用户逐条点名；AI 不得自主决定名单变更（用户 10-13 明确要求） |
| 写操作 | 三重闸门（见 §3.2）；`list_entry_delete` 提示先展示条目再删 |
| 审计 | `audit_log` 双留痕，`operator='mcp:<agent名>'`，审计页显示中文标签（如「MCP 误伤加白」） |
| 暴露面 | 默认 `0.0.0.0:8090`（内网）。如需收敛，改 `DNSF_MCP_HOST=127.0.0.1` 或在上联 ACL 限制来源 |
| 故障隔离 | MCP 进程异常不影响 DNS 解析；systemd `Restart=on-failure` 自愈 |

---

## 7. 三个典型工作流

**① 值班问答（只读）**
```
「github.com 会不会被拦？」        → domain_verdict('github.com') → allow（白名单命中）
「xyz 那个新域名什么来头？」        → domain_investigate('xxx.xyz') → 首现 2 小时前 + 注册 3 天 + DGA 0.71
「今天最该关注什么？」              → system_status + ai_report + ai_findings(threat_cluster)
```

**② 误伤治理（读 → 确认 → 写）**
```
ai_findings(finding_type='false_positive')   # 拿清单与证据（多客户端共访=最强信号）
→ 向用户复述：域名、评分、影响面
→ false_positive_whitelist(domain, confirm=true)
→ 60s 后 domain_verdict 复验 action=allow（生效延迟见工具返回 note）
```

**③ 威胁研判 → 处置**
```
ai_findings(finding_type='threat_cluster')   # 族群 = 攻击基础设施聚类
→ domain_investigate(族群代表域名)            # 交叉验证
→ 若确认恶意：blacklist_add(confirm=true) 或保留由名单源自动拦
→ finding_decide(finding_id, status='confirmed')   # 留痕「我确认这是威胁」
```

---

## 8. 验收（本次落地实测）

| 项 | 结果 |
|---|---|
| 单元/集成测试 | **48 项**（API 客户端/只读工具/写守卫/协议注册/中间件/审计端点），全量 **667 项全绿** |
| 协议端到端 | 真实 MCP 客户端 stdio 握手成功；工具 16 个（10 读 + 6 写）；提示词 2 个 |
| 生产数据实测 | `system_status` 返回今日 370 万查询 / 7.51% 拦截率 / 五层计数；`domain_verdict('github.com')`=allow（白名单）、`domain_verdict('xybpoxl.biz')`=intercept |
| 写守卫实测 | 未带 `confirm` 的 `whitelist_add` 被拒（`needs_confirmation`），库中命中条数 0（零改动） |
| 审计留痕 | `audit_log` 出现 `operator='mcp:...' / action='mcp_whitelist_add'`，审计页显示「MCP 加白名单」 |

---

## 9. 后续可扩展（未做，按需）

1. **批量与审批**：`batch_whitelist_add`（一次多域，逐条证据）+ 写操作审批流（pending → 人批 → 执行），把 `confirm` 从「调用方声明」升级为平台强制。
2. **更强资源面**：MCP `resources` 暴露 `dnsf://status`、`dnsf://findings/dga` 等可订阅资源；`subscriptions` 推变更（新族群出现即通知 Agent）。
3. **独立只读账号**：平台侧加 `mcp_viewer` 角色（只读 API 白名单），让只读模式在**权限层**也成立，而非仅靠工具层开关。
4. **工具粒度细化**：`tunnel_session_detail`、`client_timeline`（单主机时间线）等。
5. **与告警联动**：MCP 服务在发现高危族群时主动推 Agent（MCP 订阅 / Webhook）。

---

## 10. 生产部署实测记录（2026-10-13）

**部署**：`bash deploy/install-mcp.sh --api-password '<口令>' --pip-proxy http://172.16.5.7:3128`
→ MCP SDK 2.3.0 装入平台 venv → 口令校验通过 → `/etc/dnsfilter/mcp.env`（600 root）→ `dnsfilter-mcp.service` 启用（`0.0.0.0:8090/mcp`）。

| 验证项 | 结果 |
|---|---|
| 服务状态 | `active`（`MCP streamable-http 启动：http://0.0.0.0:8090/mcp`） |
| 跨网段无 Token | `HTTP 401` ✓ |
| 跨网段错 Token | `HTTP 401` ✓ |
| 跨网段正确 Token | 握手成功：`dns-security-filter v1.0.0`｜工具 **16 个（只读 10 / 写 6）** ✓ |
| 真实工具调用 | `system_status` → 今日 381 万查询 / 7.51% 拦截率；首现表 2.7 万；`domain_verdict('github.com')` → allow（白名单命中）✓ |
| 写守卫 | 未带 confirm 的 `whitelist_add` → `needs_confirmation`，库中命中条数 **0**（零改动）✓ |
| 审计留痕 | `audit_log` 双留痕（`list_create` + `mcp_whitelist_add`，operator=`mcp:<agent>`）✓ |
| 解析不受影响 | platform-dns / platform-web 全程 active，DNS 解析正常 ✓ |

### 10.1 部署中暴露并修掉的三处问题（都已回归测试覆盖）

1. **`streamable_http_app()` 不接受 `port` 参数** → 服务启动即 `TypeError`、systemd 反复重启。`port` 属于 `run_streamable_http_async`。修正后抽 `build_http_app()` 使构造路径可测（4 项回归测试）。
2. **SDK 的 DNS rebinding 防护会拒掉按内网 IP 的访问**：`0.0.0.0` 绑定但 `allowed_hosts` 不含本机网卡 IP 时，远端 `http://<IP>:8090/mcp` 直接被拒。新增 `_transport_security()`：放行回环 + localhost + 各网卡 IPv4（socket 探测）；Bearer Token 仍是主防线。
3. **`install-mcp.sh` 曾取 `platform.yaml` 的初始口令**：生产管理员改过口令，yaml 里是**首次初始化**的值——直接采用会写入过期凭据（MCP 装好但调不通平台）。改为 `--api-password` > 已有 mcp.env > yaml，且**连接前试登录校验**，不一致立即报错。另修：脚本自检的 SDK 客户端 API 需用 2.x 写法（`create_mcp_http_client` + `streamable_http_client`）。

> 附带教训：**部署脚本的自检必须真的能跑通**——这次三处问题里有两处正是靠自检与实测抓出来的；把构造逻辑抽成可测函数，比"部署时试试看"可靠得多。
