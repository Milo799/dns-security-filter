# Windows DNS 安全过滤中间件 开发 PRD（V1.2）

> 本文档基于《Windows DNS 安全过滤中间件 需求说明书-v1》编写，面向开发实现，定义数据模型、接口、配置项与技术方案。AI 开发可据此直接编码。

## 一、文档说明

| 项 | 内容 |
|----|------|
| 项目 | Windows DNS 安全过滤中间件 |
| 目标读者 | AI 开发助手 / 开发工程师 |
| 关联文档 | 《Windows DNS 安全过滤中间件 需求说明书-v1》 |
| 环境 | 纯 IPv4 内网；Windows Server 原生 DNS；网络不支持 IPv6（但客户端可能发起 AAAA 查询，需同等过滤） |
| 部署原则 | 代理中间件独立部署，Windows DNS 零安装、仅配转发器；代理与平台均以 **Linux 部署为准**（Windows 部署仅作备用） |

## 二、系统架构

### 1. 组件与职责

| 组件 | 部署 | 职责 |
|------|------|------|
| Windows DNS | 既有（可多台） | 内网解析照常；仅新增一条转发器，将外网域名转发至代理中间件；转发时透传 EDNS0 Client Subnet（RFC 7871）携带客户端 IP |
| DNS 代理中间件 | 独立部署（与 Windows DNS 不同机，可多个） | 监听 53 端口接收 Windows DNS 转发的查询，**原样透传（含 EDNS0 选项）**至安全过滤平台，回传应答 |
| DNS 安全过滤平台 | 独立服务器（单实例） | 作为 DNS 服务器接收查询 → 提取客户端 IP → 双维度检测 → 公网解析 → IP 过滤 → 返回应答；并提供 Web 管理与日志 |

### 2. 请求链路

```
内网终端
   │  DNS 查询（含 EDNS0 Client Subnet：客户端 IP）
   ▼
Windows DNS
   ├─ 内网域名 ──▶ 本地权威解析（不经过本系统）
   └─ 外网域名 ──▶ 转发器指向 代理IP:53
                        ▼
              DNS 代理中间件（转发器，独立部署）
                        │  标准 DNS 协议转发（EDNS0 原样保留）
                        ▼
              DNS 安全过滤平台（监听 53）
                        ├─ 提取 EDNS0 Client Subnet → 客户端 IP
                        ├─ 白名单 → 直接放行（原样公网解析返回）
                        ├─ 域名前置检测（本地黑名单 + 威胁情报多源融合）
                        │     ├─ 命中恶意 → 构造拦截应答返回（写日志）
                        │     └─ 无风险 → 请求公网 DNS 解析
                        ├─ IP 后置过滤（A/AAAA 解析结果逐条校验）
                        │     ├─ 全部恶意 → 构造拦截应答（写日志）
                        │     ├─ 部分恶意 → 剔除恶意、保留正常（写日志）
                        │     └─ 全部正常 → 原样返回
                        └─ 返回 DNS 应答
                        ▼
        代理回传 → Windows DNS → 内网终端
```

### 3. 协议选型

- **代理 ↔ 平台：全程标准 DNS 协议（UDP 53 + TCP 53）**
- 代理是纯 DNS 转发器，不做协议转换、不含检测逻辑、**不修改 EDNS0 选项**；
- 平台本身是一个增强型 DNS 服务器，监听 53，解析 DNS 报文、执行检测、构造应答；
- 客户端 IP 通过 **EDNS0 Client Subnet（RFC 7871）** 逐跳透传：Windows DNS 转发时自动附加客户端子网信息 → 代理原样保留 → 平台解析提取。

### 4. 客户端 IP 透传要求（EDNS0 Client Subnet）

- Windows Server 2016 及以上版本 DNS 服务器默认支持 EDNS0 Client Subnet，无需额外配置；
- 代理中间件转发时必须**完整保留查询报文的 EDNS0 选项（OPT RR）**，不得剥离或改写；
- 平台解析报文时提取 ECS 选项中的源子网（address + prefix）作为客户端标识，写入过滤日志；
- 若客户端 IP 无法获取（Windows DNS 版本过老或客户端不支持 ECS），日志中 `client_ip` 记为空，不影响过滤功能。

## 三、技术选型建议

> 非强制，AI 开发可按熟悉度调整，但需满足下述功能与性能要求。

| 组件 | 推荐方案 | 备选 | 说明 |
|------|----------|------|------|
| 代理中间件 | Go + `miekg/dns` | Python + `dnslib` | 单文件二进制部署、性能损耗可忽略 |
| 平台后端 | Python 3.10+ / FastAPI | Go / Node.js | 同时承担 DNS 服务器与 Web API，统一语言便于维护 |
| 平台 DNS 服务 | Python `dnslib` 或 `dnspython` | — | 在平台内监听 53，解析/构造 DNS 报文（需支持 EDNS0） |
| 数据库 | SQLite | PostgreSQL | 单实例足够；名单/日志/配置规模不大 |
| 前端 | Vue 3 + Element Plus | 原生 HTML + Bootstrap | 管理界面，组件化开发 |
| 部署封装 | **Linux systemd 服务（优先）** | Windows 服务（NSSM） | 代理与平台均以 systemd 守护运行；Go 单文件二进制与 Python 服务均天然跨平台，Windows 部署仅作备用 |

## 四、DNS 代理中间件规格

### 4.1 核心职责
接收 Windows DNS 转发的外网 DNS 查询（UDP/TCP 53），**原样（含 EDNS0 选项）**转发至安全过滤平台，接收平台应答后回传给 Windows DNS。**不含任何检测逻辑**。

### 4.2 配置项

| 配置项 | 说明 | 示例 |
|--------|------|------|
| `listen_addr` | 代理监听地址（绑定本机网卡 IP） | `0.0.0.0` 或具体 IP |
| `listen_port` | 监听端口 | `53` |
| `upstream_addr` | 安全过滤平台地址 | `10.0.0.50` |
| `upstream_port` | 平台端口 | `53` |
| `forward_timeout` | 转发超时（秒） | `3` |
| `log_enabled` | 代理运行日志开关 | `false`（默认关） |

配置文件格式建议 `YAML` 或 `JSON`，位于程序同目录。

### 4.3 故障行为
- 平台不可用/超时：代理返回 `SERVFAIL`（RFC 1035 RCODE=2），由 Windows DNS 侧人工切换转发器绕过；
- 代理自身不缓存、不重试、不篡改报文（含 EDNS0 选项）。

### 4.4 部署
- 部署环境以 **Linux（64 位）为准**，通过 systemd 注册服务、开机自启；提供 `.deb` / `.rpm` 打包或通用二进制 + systemd unit 模板两种方式（二选一即可）；
- 监听 53 端口需 root 权限：以 root 运行，或为二进制授予 `CAP_NET_BIND_SERVICE` 能力（`setcap 'cap_net_bind_service=+ep' <可执行文件>`）后以普通用户运行，二选一；
- 监听 53 需确保未被占用（独立机器默认空闲）；
- Windows DNS 转发器指向 `代理IP:53`；
- 可选备用：Windows 部署（NSSM 注册服务），不作为交付重点。

## 五、DNS 安全过滤平台规格

### 5.1 DNS 请求处理主流程

平台监听 53，收到 DNS 查询报文后按以下顺序处理：

```
1. 解析 DNS 查询报文 → 提取 查询域名 + 查询类型(QTYPE) + EDNS0 Client Subnet(客户端 IP)
2. QTYPE 非 A / AAAA → 直接转发公网 DNS 解析并原样返回（不做过滤）
3. 域名命中白名单 → 直接转发公网解析并原样返回（写放行日志，若开启）
4. 域名前置检测（A 与 AAAA 同等处理）：
   a. 命中本地域名黑名单 → 构造拦截应答返回（写拦截日志）→ 结束
   b. 并行调用启用的威胁情报适配器查询域名 → 按融合策略判定恶意
      → 判定恶意 → 构造拦截应答返回（写日志）→ 结束
5. 请求公网 DNS 解析 → 得到记录 IP 列表（A 得 IPv4 列表 / AAAA 得 IPv6 列表）
6. IP 后置过滤（对返回的每个 IP 逐条校验）：
   a. 命中本地 IP 黑名单（支持 CIDR）→ 剔除
   b. 对剩余 IP 并行调用威胁情报适配器 → 按融合策略判定恶意的剔除
   c. 剔除后剩余 IP 数 = 0 → 构造拦截应答返回（写日志）
   d. 剩余 IP > 0 → 用剩余 IP 构造正常应答返回（若发生剔除则写日志）
   e. 无任何剔除 → 原样返回公网解析结果
7. 构造 DNS 应答报文（保留请求中的 EDNS0 选项一致性）→ 返回给代理
```

### 5.2 黑白名单管理

**匹配规则**
- 白名单优先级最高：命中白名单跳过全部检测直接放行；
- 域名匹配支持精确匹配与通配符（`*.xxx.com` 匹配 `a.xxx.com`、`a.b.xxx.com`）；
- IP 黑名单支持精确 IP 与 CIDR 网段（如 `10.0.0.0/24`），对 IPv4 与 IPv6 地址均适用。

**功能清单**
- Web 界面增删改查；
- 批量导入（CSV）/ 导出（CSV）；
- 单条启用 / 禁用；
- 备注字段；
- 变更留痕：记录操作人、时间、操作类型、变更内容。

### 5.3 威胁情报多源集成与融合

威胁情报来源可能同时启用多个（不同厂商、不同协议），且多个源**共同参与判断**，需做好兼容与融合。

**统一适配器接口（每个情报源实现一个适配器）**

```python
class ThreatIntelAdapter:
    name: str                 # 情报源名称，如 "virustotal"
    def query_domain(self, domain: str) -> ThreatResult | None
    def query_ip(self, ip: str) -> ThreatResult | None      # ip 可为 IPv4 或 IPv6

# ThreatResult 统一返回结构
{
  "is_malicious": bool,     # 该源是否判定恶意
  "source": str,            # 情报源名称
  "detail": str,            # 详情（命中标签/报告链接等，可为空）
  "confidence": float       # 置信度 0~1（可选，多数融合策略时使用）
}
# 调用异常或超时返回 None，表示该源本次无结论
```

- 每个适配器负责：请求构造、鉴权、响应解析、统一结果映射；
- 适配器通过 Web 界面注册/启用/禁用，启用状态入库，运行时动态生效；
- 新增情报源只需新增一个适配器实现 + 配置项，不改动检测主流程。

**多源融合策略（系统配置 `fusion_strategy`，全局生效）**

| 策略 | 判定规则 | 适用场景 |
|------|----------|----------|
| `any`（默认） | 任一启用源返回恶意即判恶意 | 安全优先，宁可误报不漏报 |
| `majority` | 返回结论（非超时）的源中，超半数判恶意才判恶意 | 平衡准确率与召回 |
| `all` | 全部返回结论的源均判恶意才判恶意 | 低误报，仅严重确信时拦截 |

- 融合判定的输入为所有**成功返回结论**的适配器结果；超时/异常（None）的源不参与统计；
- **所有启用的源全部超时/故障（无任何结论）时默认拦截**（返回拦截应答），不自动放行；
- 域名检测与 IP 检测分别走各自适配器（同一源的 domain/ip 查询能力可能不同，按需实现）；
- 仅管理员可在 Web 界面临时关闭全部检测以放行（操作留痕）。

**日志中的过滤原因**
- 记录触发判定的策略与来源：如 `threatintel:any:virustotal,abuseipdb` 或 `threatintel:majority:...`。

### 5.4 拦截应答构造

| 查询类型 | 拦截应答 |
|----------|----------|
| A（请求 IPv4） | ANSWER 段返回**可配置的固定告警 IP**（单条 A 记录，TTL 可配置，默认 60s） |
| AAAA（请求 IPv6） | 返回**空应答**（ANSWER 段无记录，RCODE=NOERROR），使客户端无 IPv6 地址可用 |

- 不返回 `NXDOMAIN`、不丢弃报文；
- 告警 IP 在系统配置中统一设置，全局生效（仅用于 A 记录拦截应答）。

### 5.5 被过滤内容记录（核心）

**必录**：所有被拦截或剔除的请求，日志字段如下：

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | 自增主键 | — |
| `timestamp` | datetime | 记录时间 |
| `client_ip` | varchar | 客户端 IP（来自 EDNS0 Client Subnet，可能为空） |
| `domain` | varchar | 请求域名 |
| `query_type` | varchar | 查询类型（A / AAAA） |
| `filter_reason` | varchar | 过滤原因：`local_blacklist` / `threatintel:<策略>:<源列表>` |
| `action` | varchar | `intercept`（拦截）/ `remove_ip`（剔除部分IP） |
| `malicious_ips` | text | 命中的恶意 IP 明细（逗号分隔，IPv4/IPv6） |
| `final_result` | varchar | 最终返回：`alert_ip:<IP>` / `empty`（AAAA 拦截）/ `remaining_ips:<IP列表>` |
| `source_api` | varchar | 命中的威胁情报源名称（若适用） |

**可选日志**
- 放行记录：默认关闭，Web 界面可开启；开启后记录所有放行请求（时间、客户端 IP、域名）。

**日志管理**
- 按保留天数自动清理（可配置，默认 90 天）；
- 支持按时间范围、客户端 IP、域名、过滤原因、动作类型查询；
- 支持导出 CSV。

### 5.6 Web 管理界面

**页面清单**

| 页面 | 功能 |
|------|------|
| 登录 | 管理员账号密码登录，禁止匿名 |
| 仪表盘 | 平台运行状态：检测开关、今日拦截数、今日放行数、情报源状态 |
| 黑白名单 | 名单增删改查、导入导出、启停、备注 |
| 威胁情报源 | 适配器注册、API 配置增删改、启停、连通性测试、融合策略设置 |
| 过滤日志 | 日志查询（含客户端 IP）、导出；放行记录开关 |
| 系统配置 | 告警 IP、公网 DNS、日志保留天数、检测总开关 |
| 操作审计 | 名单变更与检测开关的操作留痕查看 |

## 六、数据模型

### 6.1 名单表 `filter_list`

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | INTEGER PK | 自增 |
| `list_type` | VARCHAR | `blacklist` / `whitelist` |
| `target` | VARCHAR | `domain` / `ip` |
| `value` | VARCHAR | 域名（含通配符）或 IP/CIDR |
| `enabled` | BOOLEAN | 启用状态 |
| `remark` | VARCHAR | 备注 |
| `created_by` | VARCHAR | 创建人 |
| `created_at` | DATETIME | 创建时间 |
| `updated_at` | DATETIME | 更新时间 |

索引：`(list_type, target, enabled)`。

### 6.2 威胁情报源配置表 `threatintel_api`

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | INTEGER PK | 自增 |
| `name` | VARCHAR | 适配器名称（唯一，如 `virustotal`） |
| `base_url` | VARCHAR | 接口地址 |
| `api_key` | VARCHAR | 密钥（加密存储） |
| `enabled` | BOOLEAN | 启用状态 |
| `timeout_ms` | INTEGER | 超时（毫秒） |
| `created_at` | DATETIME | — |
| `updated_at` | DATETIME | — |

### 6.3 过滤日志表 `filter_log`

见 5.5 节字段定义（含 `client_ip`）。索引：`timestamp`、`client_ip`、`domain`、`action`。

### 6.4 管理员表 `admin_user`

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | INTEGER PK | — |
| `username` | VARCHAR | 登录名 |
| `password_hash` | VARCHAR | 密码哈希（bcrypt） |
| `created_at` | DATETIME | — |

### 6.5 系统配置表 `system_config`

Key-Value 结构，运行时可改：

| key | 说明 | 示例默认值 |
|-----|------|-----------|
| `alert_ip` | 告警 IP（A 记录拦截应答） | `127.0.0.1`（需配置真实告警页 IP） |
| `alert_ttl` | 告警应答 TTL（秒） | `60` |
| `upstream_dns` | 公网 DNS（用于平台解析外网域名） | `8.8.8.8` 或企业指定 |
| `fusion_strategy` | 威胁情报融合策略 | `any` |
| `log_retention_days` | 日志保留天数 | `90` |
| `allow_log_enabled` | 放行日志开关 | `false` |
| `detection_enabled` | 检测总开关 | `true` |

### 6.6 操作审计表 `audit_log`

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | INTEGER PK | — |
| `timestamp` | DATETIME | — |
| `operator` | VARCHAR | 操作人 |
| `action` | VARCHAR | `list_create` / `list_update` / `detection_toggle` / `threatintel_toggle` / `fusion_strategy_change` 等 |
| `detail` | TEXT | 变更内容 JSON |

## 七、接口定义

### 7.1 代理 ↔ 平台（DNS 协议）

- 传输：UDP 53（主）+ TCP 53（大响应回退）
- 协议：标准 DNS（RFC 1035）+ EDNS0（RFC 6891），平台作为 DNS 服务器应答
- **EDNS0 Client Subnet（RFC 7871）必须完整透传与解析**：代理保留、平台提取客户端 IP 用于日志
- 无自定义 API，代理无需感知平台内部结构

### 7.2 Web 管理 API（REST / JSON）

> 所有接口除 `/auth/login` 外需携带 `Authorization: Bearer <token>`，无 Token 或无效返回 `401`。

**认证**

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/auth/login` | 登录，返回 JWT；Body: `{username, password}` |
| POST | `/api/auth/logout` | 登出 |

**黑白名单**

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/list` | 查询列表；Query: `list_type, target, keyword, page, size` |
| POST | `/api/list` | 新增单条 |
| PUT | `/api/list/{id}` | 修改 |
| DELETE | `/api/list/{id}` | 删除 |
| POST | `/api/list/import` | 批量导入（CSV 上传） |
| GET | `/api/list/export` | 导出（CSV 下载） |

**威胁情报源**

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/threatintel` | 查询情报源配置列表 |
| POST | `/api/threatintel` | 新增/注册适配器配置 |
| PUT | `/api/threatintel/{id}` | 修改 |
| DELETE | `/api/threatintel/{id}` | 删除 |
| POST | `/api/threatintel/{id}/test` | 连通性测试（域名/IP 均可） |
| PUT | `/api/threatintel/fusion-strategy` | 修改融合策略；Body: `{strategy: "any"\|"majority"\|"all"}` |

**过滤日志**

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/logs` | 查询；Query: `start, end, client_ip, domain, action, reason, page, size` |
| GET | `/api/logs/export` | 导出 CSV |

**系统配置 / 状态**

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/config` | 读取系统配置 |
| PUT | `/api/config` | 修改配置（告警IP、DNS、保留天数等） |
| GET | `/api/status` | 平台运行状态（检测开关、计数、情报源状态） |
| POST | `/api/detection/toggle` | 切换检测总开关；Body: `{enabled: bool}` |

**审计**

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/audit` | 查询操作留痕；Query: `start, end, operator, action, page, size` |

**统一响应格式**
```json
{ "code": 0, "message": "ok", "data": {} }
```
- `code=0` 成功；非 0 失败，`message` 描述原因。

## 八、配置项清单

| 配置项 | 所属组件 | 说明 | 默认 |
|--------|----------|------|------|
| `listen_addr/port` | 代理 | 监听地址与端口 | `0.0.0.0:53` |
| `upstream_addr/port` | 代理 | 平台地址 | — |
| `forward_timeout` | 代理 | 转发超时 | `3s` |
| `alert_ip` | 平台 | 告警 IP（A 记录） | 需配置 |
| `alert_ttl` | 平台 | 告警应答 TTL | `60s` |
| `upstream_dns` | 平台 | 公网 DNS | `8.8.8.8` |
| `fusion_strategy` | 平台 | 多源融合策略：`any` / `majority` / `all` | `any` |
| `log_retention_days` | 平台 | 日志保留 | `90` |
| `allow_log_enabled` | 平台 | 放行日志 | `false` |
| `detection_enabled` | 平台 | 检测总开关 | `true` |
| `api_timeout_ms` | 平台 | 威胁情报源单次调用超时 | `2000` |

## 九、非功能要求

- **部署环境**：代理与平台以 **Linux（64 位）为准**（如 Ubuntu 20.04+ / CentOS 7+ 等主流发行版），systemd 服务管理；平台 Python 3.10+、代理 Go 编译二进制，均可直接在 Linux 上运行；Windows 部署仅作备用；
- **纯 IPv4 网络**：内网为纯 IPv4；但对 AAAA 查询**同等执行过滤流程**（域名前置 + IPv6 地址后置过滤），拦截时返回空应答；
- **性能参考**：单实例支撑 500 QPS 外网查询，检测路径延迟增量 < 200ms（威胁情报调用为主要耗时，多源并行可缓解）；
- **资源参考**：平台 4 核 4G、日志盘 50G 起；代理 1 核 1G；
- **安全**：Web 管理禁止匿名、密码 bcrypt 存储、API Key 加密存储、管理接口仅限内网访问；
- **可回退**：所有配置可恢复默认，转发器配置可一键回退至公网 DNS。

## 十、交付物清单

| # | 交付物 | 说明 |
|---|--------|------|
| 1 | DNS 代理中间件 | 可执行程序 + 配置文件模板 + **Linux systemd 安装脚本**（Windows 服务脚本可选）；须完整透传 EDNS0 |
| 2 | DNS 安全过滤平台服务 | 可执行程序 / Python 包 + 配置文件 + **Linux systemd 安装脚本**（Windows 服务脚本可选） |
| 3 | Web 管理前端 | 静态文件包，随平台部署 |
| 4 | 数据库初始化脚本 | 建表 SQL / ORM 迁移脚本 + 默认管理员账号初始化 |
| 5 | 威胁情报适配器框架 | 统一适配器接口 + 融合判定模块 + 至少 1 个免费情报源适配器示例 |
| 6 | 部署文档 | Linux 下的安装部署（systemd 注册、防火墙放行 53/UDP+TCP）、配置、转发器配置、回退步骤 |

## 十一、补充说明

- **客户端 IP**：通过 EDNS0 Client Subnet（RFC 7871）实现——Windows DNS 转发时附加客户端子网，代理原样透传，平台解析后写入日志。若个别客户端/旧版 Windows DNS 不携带 ECS，`client_ip` 记为空，不影响过滤；
- **缓存**：平台与代理均不缓存 DNS 记录，避免过期投毒与缓存一致性问题；
- **DNSSEC**：本架构会修改应答，客户端不应启用 DNSSEC 校验；
- **根提示**：建议 Windows DNS 禁用 Root Hints，确保外网请求必经转发器，避免绕过过滤。

---

> 本 PRD 可直接交付 AI 开发助手进行实现。开发过程中如遇技术选型或接口设计需调整，建议与需求方确认后变更。
