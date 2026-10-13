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

**四条硬约束（写进代码，不是口号）：**

1. **不直连数据库**：所有读写都经平台 Web API——复用既有鉴权、参数校验、`invalidate_list_cache()` 缓存失效、审计留痕。新增旁路写入口是安全大忌。
2. **写操作三重闸门**：
   - 进程开关 `DNSF_MCP_ALLOW_WRITE`（0 = 只读模式，写工具一律返回 `write_disabled`）
   - 调用方 `confirm=true`（缺省返回 `needs_confirmation` + `pending_action`，供 Agent 向用户复述）
   - 平台侧审计（`audit_log` 同时留两条：API 业务审计 + `mcp_<工具>` 归属审计）
3. **AI 只出建议**：MCP 不提供「自动加白」「自动拦截」——`false_positive_whitelist` 也必须带 `confirm=true`，语义是「人已确认，Agent 代按」。
4. **生产零依赖**：MCP 挂了只影响 Agent 操作，DNS 解析与检测链路完全不受影响（它是旁路进程）。

---

## 4. 部署

```bash
# 机 B（检测平台）部署完平台之后
sudo ./deploy/install-mcp.sh                      # 读写模式，端口 8090
sudo ./deploy/install-mcp.sh --read-only          # 只读模式（推荐先这样试）
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
| `DNSF_MCP_ALLOW_WRITE` | 1 | 0 = 只读模式 |
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

## 6. 安全边界

| 面 | 措施 |
|---|---|
| 传输 | http 强制 Bearer Token；Token 随机 32 字节（`token_urlsafe`），存 600 权限文件 |
| 权限 | 等于平台 admin（能调用的 API 都能调）——**因此建议先以 `--read-only` 上线**，确认场景后再开写 |
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
