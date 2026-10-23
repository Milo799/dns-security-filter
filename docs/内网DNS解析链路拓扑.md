# 内网 DNS 解析链路拓扑

> **2026-10-23 由用户口述 + 对各节点原始 DNS 报文实测确认。**
>
> 本文是排障时的**权威参照**。MCP 服务的 `instructions` 里已内嵌精简版
> （见 `platform/mcp_server.py` 的 `_TOPOLOGY_CONTEXT`），Agent 调用 MCP
> 工具时会自动获得本拓扑上下文。

---

## 一、为什么需要这份文档

`domain_verdict` / `logs_query` 只能看到**本平台（172.16.0.191）这一层**的判定，
但客户端的实际访问链路有 5 跳。

2026-10-23 的 F5 排查就是典型案例：域名访问不通，
Agent 先后误判为「白名单没覆盖全」→「.8 内网 DNS 伪造 NXDOMAIN」，
实际断点在 **.7.1**，而 Agent 一度考虑在平台侧反复加白——
**方向完全错了**。

有了本文，排查第一步就能定位断点在哪一跳。

---

## 二、完整链路

```
┌─ 客户端 ──────────────────────────────────────────────┐
│  DNS 查询 → 172.16.0.8 / 172.16.0.3（域控 DNS，双机）    │
└───────────────────────────────────────────────────────┘
                          │
                          ▼
┌─ 域控 172.16.0.8 / .3 ────────────────────────────────┐
│  ① nimble.cn 本地域        → AD 本地解析                │
│  ② 条件转发器（白名单域）   → 172.16.7.2（白名单服务器）   │
│  ③ 常规外部域（DNS 转发器）→ 172.16.7.1                 │
└───────────────────────────────────────────────────────┘
                          │
                          ▼
┌─ 172.16.7.1（转发器 + 自有公网域名封禁表）─────────────┐
│  ④ 本地封禁表命中的公网域  → 封禁（NXDOMAIN）            │
│  ⑤ 未被封禁               → 转发到 172.16.0.192          │
└───────────────────────────────────────────────────────┘
                          │
                          ▼
┌─ 172.16.0.192（Go 代理 / DNS 中间件）─────────────────┐
│  ⑥ 注入 EDNS0 ECS（客户端真实 IP，Task#158）           │
│     原样转发，不修改报文（forward.go）                  │
└───────────────────────────────────────────────────────┘
                          │
                          ▼
┌─ 172.16.0.191（AI 安全 DNS 服务 / 平台）──────────────┐
│  ⑦ 五层检测：本地名单 / 离线大名单 / NRD / 在线情报 / IP后置 │
│     命中 → 返回 alert_ip 127.0.0.1                      │
│     放行 → 查上游 223.5.5.5                             │
└───────────────────────────────────────────────────────┘
                          │
                          ▼
                    223.5.5.5（阿里公共 DNS）
```

**平台 API**：`172.16.0.191:8080`（MCP 工具连的就是这里）
**平台 DNS 服务**：`172.16.0.191:53/udp`
**Go 代理**：`172.16.0.192:53/udp+tcp`

---

## 三、节点职责速查

| 节点 | 角色 | 端口 | 关键特征 |
|---|---|---|---|
| 172.16.0.8 / .3 | 域控 DNS（双机） | 53 | AD 权威解析 nimble.cn；条件转发器 + 转发器 |
| 172.16.7.1 | 转发器 + **自有公网域名封禁表** | 53 | 封禁响应 = **NXDOMAIN** |
| 172.16.7.2 | 白名单服务器 | 53 | 仅域控条件转发器命中的域；隔离网段，从客户端网段不可达 |
| 172.16.0.192 | Go 代理（DNS 中间件） | 53/udp+tcp | 注入 ECS；原样回传平台应答 |
| 172.16.0.191 | 拦截服务（平台） | 53/udp, 8080/tcp | 五层检测；拦截响应 = **127.0.0.1** |
| 172.16.5.7 | 出口 HTTP 代理 | 3128 | 平台 config.http_proxy |

---

## 四、排障决策树

### 第一步：判断断点在哪一跳

用**原始 DNS 报文**（不要只信 nslookup 的文字输出）逐跳测：

```python
import socket, struct
def q(name, server, qtype=1, timeout=6):
    hdr = struct.pack('>HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
    b = b''
    for p in name.split('.'):
        b += bytes([len(p)]) + p.encode()
    b += b'\x00' + struct.pack('>HH', qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(hdr + b, (server, 53))
    d, _ = s.recvfrom(4096)
    s.close()
    return d[3] & 0x0F, struct.unpack('>H', d[6:8])[0]   # rcode, ancount
```

对照表：

| rcode / answer | 判断 |
|---|---|
| NOERROR + ancount=0 | 域名有效但无记录（CDN 中间 CNAME 节点的正常表现） |
| NOERROR + an=1 + 127.0.0.1 | **本平台拦截**（有 logs 记录） |
| NXDOMAIN | **.7.1 拦截或 CNAME 缺陷**（无本平台 logs 记录） |
| SERVFAIL | 平台不可达 / 熔断 / failsafe degrade |
| TIMEOUT | 该节点从你所在网段不可达 |

### 第二步：按响应形式定位

| 现象 | 断点 | 该做什么 |
|---|---|---|
| 有 logs 记录 + 127.0.0.1 | **.191 本平台** | 查 platform 的 threatlist / list_query |
| 无 logs 记录 + NXDOMAIN | **.7.1** | 查 .7.1 的自有封禁表 / CNAME 处理逻辑 |
| 有 logs 记录 + 正常 IP，但访问仍不通 | 上游网络 / 出口代理 | 查 172.16.5.7:3128 代理策略 |

### 第三步：核对 CNAME 链每一跳

域名「被拦」和「访问不通」是两件事。CNAME 链任一跳断了都会访问不通，
而每一跳都要单独验证：

```
www.f5.com
  └─ CNAME → ves-io-8034cc52-….ac.vh.ves.io
       └─ CNAME → ac.vh.ves.io
            └─ A → 159.60.134.0
```

---

## 五、已知外部断点（不属于本平台）

### 断点 A：.7.1 对「纯 CNAME 顶级域」返回 NXDOMAIN

**规律**：顶级域自身无 A 记录、只靠 CNAME 指向 CDN 的域，.7.1 一律 NXDOMAIN。
自身带 A 记录的域正常。

| 被误杀（NXDOMAIN） | 正常 |
|---|---|
| ves.io、npmjs.io、crates.io、golang.io | github.io、pypi.org |
| rust-lang.io、readthedocs.io | docker.io、quay.io |
| intercom.io、sentry.io、segment.io、branch.io | go.dev、golang.org |
| ac.vh.ves.io | registry.npmjs.org |

**连带影响**：**Go / Rust / Python 开发工具链在这套网络里不可达**
（crates.io = Rust 包仓库，golang.io = Go 官网）。

**优先排查项**：UUID 风格的 CNAME 标签
（如 `ves-io-8034cc52-3060-4606-a8f3-7ba79c6d0bde`）
极易被 **DGA / 熵值检测误判**——与平台自己的 DGA 检测是同一类特征。

**平台加白无效**（请求根本没到平台）。

### 断点 B：.7.2 白名单只覆盖域控条件转发器

.7.2 已有「白名单服务器」角色，但只对域控条件转发器命中的域生效；
**.7.1 这一层没有对应的放行机制**，两套名单各自为政。

建议：让 .7.1 也支持条件转发到 .7.2，或统一到平台侧管理。

---

## 六、两套封禁的响应形式不一致（易误判）

| 封禁方 | 响应 | 浏览器表现 |
|---|---|---|
| 平台 .191 | `127.0.0.1`（告警应答） | 跳转到告警页 |
| .7.1 自有表 | `NXDOMAIN` | 「无法解析此主机」 |

**同一个域名在两层被封，客户端现象完全不同。**
建议 .7.1 也统一用 `127.0.0.1`，与平台告警页联动。

**判别铁证**：`intercom.io` 在 .192 返回真实 IP（平台放行），
在 .7.1 被 NXDOMAIN → 说明 .7.1 有独立封禁表。

---

## 七、实测证据存档

### 各层对同一域名的应答

| 域名 | .8 域控 | .3 域控2 | .7.1 | .192 Go代理 |
|---|---|---|---|---|
| ac.vh.ves.io | NXDOMAIN | NXDOMAIN | NXDOMAIN | **NOERROR** |
| ves.io | NXDOMAIN | NXDOMAIN | NXDOMAIN | **NOERROR 72.19.3.143** |
| npmjs.io | NXDOMAIN | NXDOMAIN | NXDOMAIN | **NOERROR 140.82.112.17** |
| crates.io | NXDOMAIN | NXDOMAIN | NXDOMAIN | **NOERROR 4×IP** |
| github.io | NOERROR | NOERROR | NOERROR | NOERROR |
| www.f5.com | 仅 CNAME | 仅 CNAME | 仅 CNAME | **CNAME + A 159.60.134.0** |
| spinfo.wps.cn | 127.0.0.1 | 127.0.0.1 | 127.0.0.1 | 127.0.0.1 |
| adsrvbk.nimble.cn | **172.16.0.8** | — | NXDOMAIN | NXDOMAIN |

- `spinfo.wps.cn` 三层一致返回 127.0.0.1 → **.7.1 确实是转发到 .192 的**
- `adsrvbk.nimble.cn` 只有域控能解析 → **证明本地域优先走 AD**

### .7.1 自有封禁表证据

| 域名 | .7.1 | .192 | 说明 |
|---|---|---|---|
| intercom.io | **NXDOMAIN** | **65.8.180.113（真实IP）** | .7.1 单独封禁 |
| sentry.io | NXDOMAIN | 127.0.0.1 | 封禁形式不同 |
| segment.io | NXDOMAIN | 127.0.0.1 | 同上 |
| branch.io | NXDOMAIN | 127.0.0.1 | 同上 |
| doubleclick.net | 127.0.0.1 | 127.0.0.1 | 平台封禁，透传 |
| mixpanel.com | 127.0.0.1 | 127.0.0.1 | 同上 |
| taboola.com | 127.0.0.1 | 127.0.0.1 | 同上 |

---

## 八、工具使用注意

⚠️ **nslookup 会把「NOERROR + 空 answer」显示成空白**，极易误判。
判断 DNS 拦截时必须看原始报文的 rcode 与 ancount，
或用 `nslookup -type=CNAME` / `-type=A` 分别确认。

判断「域名是否被拦」以 MCP 的 `domain_verdict` 为准；
判断「访问是否通」要同时核对 CNAME 链每一跳。

---

## 九、相关文档

- `docs/Windows DNS 安全过滤中间件 MCP 服务方案 V1.0.md` —— MCP 服务设计
- `docs/生产部署实操手册（AlmaLinux 8 · 单文档版）.md` —— 部署
- `proxy/main.go` Task#158 注释 —— client_ip 为空的根因说明
- `proxy/forward.go` —— Go 代理「原样回传」的证据
