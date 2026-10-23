# dns-security-filter MCP 服务 · AI Agent 接入与使用指南

> **给 AI Agent 的说明**：读完本文，你就能完成安装、配置、调用与排障。
> 本文件是**自包含**的——不需要再读别的文档。
>
> 版本：2026-10-23 ｜ 适用平台：dns-security-filter（企业 DNS 安全过滤中间件）
> 仓库：https://github.com/Milo799/dns-security-filter

---

## 0. 你将得到什么

一个提供 **16 个工具**的 MCP 服务（10 只读 + 6 写），让 AI 能：
- 查询今日 DNS 拦截总量、拦截率、五层分布
- 判定任意域名「会被拦吗、命中哪条规则」
- 追溯域名的 AI 分析结论（DGA / DNS 隧道 / 威胁族群 / 误报）
- 查询黑名单与白名单条目
- 检索拦截日志
- **在获得用户逐条明确同意后**执行名单变更

---

## 1. 先读这一段：平台架构（决定你如何排障）

```
客户端 → 域控 DNS 172.16.0.8 / .3
  ├ nimble.cn 本地域 → AD 本地解析
  ├ 条件转发器(白名单域) → 172.16.7.2（白名单服务器）
  └ 常规外部域 → 转发器 → 172.16.7.1
      ├ .7.1 自有公网域名封禁表命中 → NXDOMAIN
      └ 未封禁 → 172.16.0.192（Go 代理，注入 ECS）
          └ 172.16.0.191 ← 本 MCP 对应的平台 → 上游 223.5.5.5
```

### 五层检测（本平台职责，.191）

| 层 | 名称 | 数据量 | 说明 |
|---|---|---|---|
| L1 | 本地黑白名单 | 291 | 人工维护，最高优先级 |
| L2 | 离线大名单 | 24.5 万+ | 10 个源：hagezi_ti / hagezi_ult / hagezi_mini / hagezi_nrd / stevenblack / urlhaus / oisd / threatfox / c2intel / silverfox |
| L3 | NRD 新注册域名 | — | 在线 RDAP，检测 TLD：xyz,top,icu,shop,online,site,cfd,sbs,rest,cyou |
| L4 | 在线情报 | — | spamhaus_zen / spamhaus_dbl / dronebl / spfbl |
| L5 | IP 后置过滤 | — | 解析后按 IP 判定 |

**命中即返回告警应答 `alert_ip = 127.0.0.1`**（TTL 60s）。

### ⚠️ 排障铁律：先定位断点在哪一跳

`domain_verdict` / `logs_query` **只能看到 .191 这一层**。
但客户端实际链路有 5 跳。**用户说"某域名访问不通"时，不要默认是本平台拦的。**

| 现象 | 断点 | 该做什么 |
|---|---|---|
| 有 logs 记录 + 返回 127.0.0.1 | **.191 本平台** | 查 threatlist / list_query，给出名单证据 |
| 无 logs 记录 + NXDOMAIN | **.7.1** | 提示用户查 .7.1 的自有封禁表，**平台加白无效** |
| 有 logs + 正常 IP 但仍不通 | 上游网络 / 出口代理 | 查 172.16.5.7:3128 |

### 已知的外部断点（不在本平台，AI 不要在这里加白）

**① .7.1 对「顶级域自身无 A 记录、只靠 CNAME 挂 CDN」的域名返回 NXDOMAIN**

被误杀：`ves.io` `npmjs.io` `crates.io` `golang.io` `rust-lang.io`
`readthedocs.io` `intercom.io` `sentry.io` `segment.io` `branch.io`
正常：`github.io` `pypi.org` `docker.io` `quay.io` `go.dev` `golang.org`

**连带影响：Go / Rust / Python 开发工具链在这套网络里不可达**
（crates.io = Rust 包仓库，golang.io = Go 官网）。

优先排查项：**UUID 风格的 CNAME 标签**
（如 `ves-io-8034cc52-3060-4606-a8f3-7ba79c6d0bde`）
极易被 DGA / 熵值检测误判 —— 与本平台自己的 DGA 检测是同一类特征。

**② .7.2 白名单服务器仅对域控条件转发器命中的域生效**，.7.1 这层没有对应机制。

### ⚠️ nslookup 的坑

`nslookup` 会把 **「NOERROR + 空 answer」显示成空白**。
判断 DNS 拦截必须看**原始报文的 rcode 与 ancount**，否则会把
「域名有效但无 A 记录」误判成「被 NXDOMAIN 拦截」。

```python
import socket, struct
def dnsq(name, server, qtype=1, timeout=6):
    hdr = struct.pack('>HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
    b = b''
    for p in name.split('.'):
        b += bytes([len(p)]) + p.encode()
    b += b'\x00' + struct.pack('>HH', qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    s.sendto(hdr + b, (server, 53)); d, _ = s.recvfrom(4096); s.close()
    rcode = d[3] & 0x0F
    ancount = struct.unpack('>H', d[6:8])[0]
    return {0:'NOERROR',2:'SERVFAIL',3:'NXDOMAIN',5:'REFUSED'}.get(rcode, rcode), ancount
```

---

## 2. 安装

### 方式一：stdio 模式（推荐给本地 AI 工具）

**适用于**：WorkBuddy / CodeBuddy / Claude Code / Cursor 等本地工具。

#### 步骤 1 · 拉取代码

```bash
git clone https://github.com/Milo799/dns-security-filter.git
cd dns-security-filter
```

#### 步骤 2 · 准备 Python 环境

需要 Python ≥ 3.10（推荐 3.12+）与 `mcp` SDK：

```bash
python3 -m venv venv
./venv/bin/pip install -r platform/requirements-mcp.txt
```

> Windows：`.venv\Scripts\pip install -r platform\requirements-mcp.txt`

#### 步骤 3 · 注册到 AI 工具

**WorkBuddy / CodeBuddy** — 编辑 `~/.workbuddy/mcp.json`：

```json
{
  "mcpServers": {
    "dns-security-filter": {
      "type": "stdio",
      "command": "/绝对路径/dns-security-filter/venv/bin/python",
      "args": ["/绝对路径/dns-security-filter/platform/mcp_server.py"],
      "env": {
        "DNSF_API_BASE": "http://172.16.0.191:8080",
        "DNSF_API_USER": "admin",
        "DNSF_API_PASSWORD": "你的平台管理员口令",
        "DNSF_MCP_ALLOW_WRITE": "0",
        "DNSF_MCP_TIMEOUT": "20",
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

**Claude Code** — 一次性命令：

```bash
claude mcp add dns-security-filter -- \
  --transport stdio \
  --env DNSF_API_BASE=http://172.16.0.191:8080 \
  --env DNSF_API_USER=admin \
  --env DNSF_API_PASSWORD='你的平台管理员口令' \
  --env DNSF_MCP_ALLOW_WRITE=0 \
  -- /绝对路径/dns-security-filter/venv/bin/python \
     /绝对路径/dns-security-filter/platform/mcp_server.py
```

**Cursor / 其他支持 `mcpServers` 的工具** — 同 WorkBuddy 的 JSON 结构，放到
`~/.cursor/mcp.json`。

#### 步骤 4 · 验证

```bash
# 确认 MCP 服务能启动并握手
cd dns-security-filter/platform
./../venv/bin/python -c "
import asyncio
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters

async def main():
    p = StdioServerParameters(
        command='/绝对路径/venv/bin/python',
        args=['mcp_server.py'],
        env={'DNSF_API_BASE':'http://172.16.0.191:8080',
             'DNSF_API_USER':'admin','DNSF_API_PASSWORD':'你的口令',
             'DNSF_MCP_ALLOW_WRITE':'0','PYTHONIOENCODING':'utf-8'})
    async with stdio_client(p) as (r, w):
        async with ClientSession(r, w) as s:
            init = await s.initialize()
            print('instructions 长度:', len(init.instructions or ''))
            print('工具数:', len((await s.list_tools()).tools))
asyncio.run(main())
"
```

预期输出 `工具数: 16`。

### 方式二：HTTP 模式（给远程 / 多人共用）

生产已在 `http://172.16.0.191:8090/mcp` 跑着 HTTP 模式，**强制 Bearer Token**：

```bash
sudo ./deploy/install-mcp.sh --api-base http://127.0.0.1:8080 \
  --api-password '你的平台管理员口令'
# token 默认自动生成并写入 /etc/dnsfilter/mcp.env（600 权限）
grep DNSF_MCP_TOKEN /etc/dnsfilter/mcp.env
```

客户端配置：

```json
{
  "mcpServers": {
    "dns-security-filter": {
      "type": "http",
      "url": "http://172.16.0.191:8090/mcp",
      "headers": { "Authorization": "Bearer <DNSF_MCP_TOKEN>" }
    }
  }
}
```

---

## 3. 环境变量

| 变量 | 必填 | 默认 | 说明 |
|---|---|---|---|
| `DNSF_API_BASE` | 是 | — | 平台 Web API 地址，如 `http://172.16.0.191:8080` |
| `DNSF_API_USER` | 是 | `admin` | 平台用户名 |
| `DNSF_API_PASSWORD` | 是 | — | 平台口令（也可用 `DNSF_API_PASSWORD_FILE`） |
| `DNSF_MCP_ALLOW_WRITE` | 否 | **`0`（只读）** | 设为 `1` 才允许写操作 |
| `DNSF_MCP_TOKEN` | HTTP 模式必填 | 自动生成 | Bearer Token |
| `DNSF_MCP_TIMEOUT` | 否 | `20` | API 超时秒数 |
| `DNSF_MCP_AGENT` | 否 | `mcp-agent` | 审计日志里的操作者标识 |
| `DNSF_MCP_HOST` / `_PORT` / `_TRANSPORT` | 否 | `0.0.0.0` / `8090` / `http` | HTTP 模式监听 |

---

## 4. 工具清单（16 个）

### 只读工具（10 个）—— 随便用

| 工具 | 用途 | 关键参数 |
|---|---|---|
| `system_status` | **今日拦截总览 + 五层分布 + 健康状态 + AI 结论规模** | 无 |
| `traffic_stats` | 今日总览 + 按小时拦截趋势 + 五层分布 | `hours`（1~168） |
| `domain_verdict` | **判定某域名实际处置结果（拦还是放、命中哪条规则）** | `domain`、`query_type`(A/AAAA/PTR) |
| `domain_investigate` | 域名画像：首现时间、注册时间、AI 结论、拦截史 | `domain` |
| `list_query` | 查黑白名单条目（含 id，便于后续停用/删除） | `list_type`、`keyword`、`page`、`size` |
| `logs_query` | 检索拦截日志 | `domain`、`client_ip`、`action`、`reason`、`start`、`end`、`size` |
| `ai_findings` | AI 分析结论（含评分与可解释证据） | `finding_type`、`status`、`min_score`、`limit` |
| `ai_ask` | 自然语言问平台（需平台配了 LLM） | `question` |
| `ai_report` | 生成日报 | `scope` |
| `intel_sources` | 情报源启用状态 | 无 |

### 写工具（6 个）—— ⚠️ 三重闸门

| 工具 | 作用 |
|---|---|
| `whitelist_add` | 加白名单（支持 `*.example.com` 通配） |
| `blacklist_add` | 加黑名单 |
| `false_positive_whitelist` | 把 AI 判定的误报一键加白 |
| `list_entry_set_enabled` | 启停名单条目 |
| `list_entry_delete` | 删除名单条目 |
| `finding_decide` | 对 AI 结论标记 confirmed / dismissed（不改拦截策略） |

> **`false_positive_whitelist` 是写工具**，尽管名字里有 "whitelist" 之外的语义。
> 它会同时改白名单**并**把 AI 结论标记为 confirmed —— 属写操作，同样受三重闸门约束。
>
> **`finding_decide` 是写工具**（会落库持久化人的判断），但**不改变任何拦截策略**，
> 可用于记录「这条 AI 结论是误报」的结论，避免后续反复复审。

---

## 5. 🔴 红线：写操作的正确姿势

**这是最重要的一节，请务必读完。**

### 5.1 三重闸门

1. **服务默认只读**（`DNSF_MCP_ALLOW_WRITE` 默认 `0`）。
   只读模式下所有写工具返回 `write_disabled` —— **这是预期行为，不要重试、不要绕过**。
2. **必须带 `confirm=true`**。不带则返回 `needs_confirmation`。
3. **必须获得用户在当前对话中的逐条明确同意**。

### 5.2 AI 绝不能做的事

- ❌ 看到 `ai_findings` 里有 `false_positive` 就自动加白
- ❌ 用户说"帮我优化一下名单"就批量改动
- ❌ 用户说"加白"但没点名具体域名，就自行推断要加哪些
- ❌ 因为"分析结论显示它可疑"就自作主张加黑名单

**理由**：白/黑名单是**直接影响业务可达性**的策略。改错会中断业务系统访问。
AI 只能提供**建议与证据**，落策略必须由人决定。

### 5.3 正确流程（照抄这个模式）

```
第 1 步：list_query 拿到「要改哪条、当前值、影响面」
第 2 步：向用户复述——改哪个名单、哪条域、为什么、影响什么业务
第 3 步：得到用户明确同意
第 4 步：带 confirm=true 调用写工具
第 5 步：告知生效延迟（≤60s，缓存重载），稍候再验证
```

**只有用户在当前对话中明确点名了具体条目，才可带 confirm=true 调用。**

### 5.4 加白前必做：先跑 domain_verdict

**不要凭 AI 结论就加白。** 实测教训：`netease.com` / `azure.com`
被 AI 判为"DNS 隧道嫌疑"，但 `domain_verdict` 实测两者都是 **forward（放行）**——
**根本没被拦截**。给它们加白对结果毫无改变，却把整个 azure 顶级域塞进白名单，
形成巨大安全开口。

```
先 domain_verdict(domain) → 看 final_verdict.action
  ├ action=intercept 且是误伤 → 才考虑加白
  └ action=forward/allow     → 不需要加白，标记 dismissed 即可
```

---

## 6. 典型工作流

### 6.1 每日巡检

```
system_status()                      → 总量、拦截率、五层分布、健康状态
traffic_stats(hours=24)              → 哪个时段哪一层在挨打
```

### 6.2 用户问「XX 域名能访问吗 / 为什么被拦」

```
domain_verdict(domain="xx.com", query_type="A")
  → final_verdict.action = allow   → 没被拦
  → final_verdict.action = intercept → 命中哪层哪条规则
```

### 6.3 用户问「今天拦截情况怎么样」

```
system_status()                      → 概览
traffic_stats(hours=12)             → 趋势
logs_query(action="intercept", size=30)  → 最新拦截样例
```

### 6.4 误报治理闭环

```
ai_findings(finding_type="false_positive", status="pending")
  → 把清单给用户确认（说明改哪个域、为什么、影响面）
  → 得到用户明确同意
  → false_positive_whitelist(domain="xx.com", confirm=true)
```

⚠️ `false_positive_whitelist` **是写操作**，必须带 `confirm=true`，
且必须先取得用户对**具体域名**的明确同意。
另外——加白前先跑 `domain_verdict` 确认该域名真的被拦（见 §5.4）。

### 6.5 未知威胁排查

```
ai_findings(finding_type="dga_suspect", min_score=0.7)      # DGA 域名
ai_findings(finding_type="tunnel_suspect", min_score=0.7)   # DNS 隧道
ai_findings(finding_type="threat_cluster")                   # 攻击基础设施聚类
ai_findings(finding_type="client_anomaly")                   # 异常客户端（失陷主机）
```

### 6.6 用户说「XX 域名访问不通」—— 完整排查流程

```
第 1 步：domain_verdict(xx) 确认本平台是否拦截
   ├ action=intercept → 是本平台拦的 → 给出命中规则与证据
   └ action=forward   → 本平台没拦 → 走第 2 步

第 2 步：logs_query(domain="xx") 看有没有日志
   ├ 有日志   → 本平台经手过但放行了
   └ 无日志   → 请求没到本平台，断点在别处

第 3 步：核对 CNAME 链每一跳（用原始 DNS 报文，见 §1）
   → 定位是哪一跳断了

第 4 步：按 §1 的断点表给出结论
   → .7.1 的 CNAME 缺陷 / .7.1 自有封禁表 → 明确告知平台加白无效
```

---

## 7. 常见问题

| 现象 | 原因 | 处理 |
|---|---|---|
| 写工具返回 `write_disabled` | 服务只读（默认） | 预期行为，让用户在管理端页面操作；或管理员临时设 `DNSF_MCP_ALLOW_WRITE=1` 重启服务（**用完立即改回**） |
| 写工具返回 `needs_confirmation` | 没带 `confirm=true` | 先向用户说明改动内容并取得明确同意，再带 confirm=true 重调 |
| 返回 `未认证` | 平台口令错或 token 过期 | 核对 `DNSF_API_PASSWORD` / `DNSF_MCP_TOKEN` |
| 返回 `POST /api/test/domain 失败（HTTP 400）：query_type 须为 A/AAAA/PTR` | 传了非法 query_type | 只支持这三种 |
| 日志里 `client_ip` 全为空 | 生产代理二进制是旧版，缺 ECS 注入 | 到代理机执行 `dns-proxy -version`，确认 rev 含 Task#158；否则重新编译部署 |
| `domain_verdict` 说 forward，但浏览器打不开 | 断点不在本平台 | 走 §6.6 第 2–4 步 |
| nslookup 显示空白 | 可能是 NOERROR + 空 answer | 用原始报文看 rcode/ancount（§1） |

---

## 8. 部署与运维速查

```bash
# 服务管理
systemctl status dnsfilter-mcp
systemctl restart dnsfilter-mcp
journalctl -u dnsfilter-mcp -f

# 配置与凭据
grep DNSF_MCP_TOKEN /etc/dnsfilter/mcp.env    # Bearer Token（600 权限）
vim /etc/dnsfilter/mcp.env                      # 改完重启服务

# 平台健康
curl -s http://127.0.0.1:8080/api/health
```

**部署目录**：`/opt/dns-security-filter`
**MCP 服务**：`/opt/dns-security-filter/platform/mcp_server.py`
**HTTP 端口**：8090（强制 Bearer）｜**平台 Web**：8080（仅运维网段）｜**平台 DNS**：15353

---

## 9. 一句话总结

**先看 `system_status` 摸全貌，用 `domain_verdict` 判单域名，
用 `ai_findings` 找可疑模式，用 `logs_query` 追历史；
写操作只在用户逐条明确同意后带 `confirm=true` 执行。
排障时先定位断点在哪一跳，别在错误的产品上反复加白。**
