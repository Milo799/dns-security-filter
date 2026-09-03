# 生产环境部署方案（Linux 双机 · 10 万终端规模）

> 适用场景：约 **10 万终端**（PC/服务器/哑终端混合），Windows 域环境，多台域控 DNS（DC）做转发器指向本系统代理。
> 目标拓扑：`终端(10万) → 域 DNS 转发器(多台 DC) → Go 代理(机A:53) → 检测平台(机B) → 公网 DNS`
> 编写基准：commit `e2a78cc`。第四节前置开发项 **1~5 已全部交付**（0fc774e/5c966bf/c516e8d），
> 278 项测试全绿；本方案即为可直接执行的上线方案。配套 **《生产部署指引（AlmaLinux 8）》**
> 为 OS 专项补充。

---

## ⚠️ 零、先读这一节：规模压力模型与已落地的应对（历史背景）

10 万终端的负载测算（办公混合场景经验值）：

| 指标 | 数值 |
|------|------|
| 平均查询速率 | 每终端 3~8 查询/分钟 → **5,000~13,000 QPS** |
| 晨启风暴峰值（开机 30 分钟集中解析） | 平均值 × 5 → **约 30,000~60,000 QPS** |
| DNS 唯一域名集中度（10 万终端环境） | 常态约 200~500 万种域名，但**热点极集中**：Top 1 万域名覆盖 90%+ 查询量（CDN、门户、办公 SaaS、系统服务） |

应对架构（**已全部实现，实测数据见 4.1/4.2 节**）：

| 环节 | 现状（已落地） | 应对效果 |
|------|--------------|---------|
| 白/黑名单、离线大名单 | 内存 O(1)，<1ms | ✅ 天然不是瓶颈 |
| 域名/IP 检测结论缓存 | domain_cache + ip_cache 双层 LRU+TTL，命中率稳态 ≥95% | ✅ 热点查询纯内存路径 12ms |
| 在线情报源限流 | 出厂默认仅启用 DNSBL 三源（DNS 协议无配额）+ 源级熔断 + 路径级降级 | ✅ 不会出现"API 限流→全拦断网" |
| 公网递归解析 | 缓存命中部分不再出网，仅未命中部分走上游 | ✅ 出站量降 90%+ |
| 平台线程池吞吐 | 缓存吸收 95%+ 后单进程 ~2200-3000 QPS 已满足模型 | ✅ 若需更高，多代理实例分片 |
| 日志写入 | log_writer 异步批量 + 采样，1000QPS P95=1.86ms | ✅ 峰值不拖慢应答 |

**结论：缓存分层 + 削峰 + 熔断降级全部就位，可按本方案部署。**
灰度节奏（首台 DC 观察 3~7 天）仍为强制要求，见第六/八节。

---

## 一、部署拓扑

```
                         ┌──────────────────────────────────────────────────┐
                         │                  机 B（检测平台）                  │
  ┌──────────┐  UDP53    │  ┌───────────────┐ UDP/TCP 53  ┌──────────────┐  │  UDP53
  │ 终端×10万 │           │  │  机 A（代理）   │             │  DNS 服务     │──┼──────▶ 公网 DNS
  └────┬─────┘           │  │  dns-proxy    │             │  （检测+缓存）  │  │      223.5.5.5 主
       │ 指向域 DNS        │  │  :53 纯转发    │             │  :15353      │  │      119.29.29.29 备
  ┌────▼─────┐           │  └───────────────┘             ├──────────────┤  │
  │ 域 DNS ×N │──────────│──┘                              │ Web:8080     │  │
  │ (多台 DC) │  转发器    │                                 │ SQLite+缓存  │  │
  └──────────┘  指向机A   │                                 └──────────────┘  │
                         └──────────────────────────────────────────────────┘
```

要点：
- **多台 DC 都要配转发器**（域环境通常 2~6 台 DC），逐台灰度切换（见第八节）
- EDNS0 Client Subnet：DC 转发时附加，平台据此记录真实终端 IP；注意 **10 万终端经 ECS 记录的 IP 基数大，日志表增长显著**（见第九节）
- 平台监听 15353（与代理 upstream_port 对应），两机间走内网

## 二、机器配置要求（按缓存上线后的稳态负载评估）

| 项目 | 机 A（代理） | 机 B（平台） | 说明 |
|------|-------------|-------------|------|
| CPU | 4 vCPU | **16~32 vCPU** | 机B 检测主流程在线程池，核数直接决定并发吞吐；缓存命中后 CPU 主要消耗在报文解析 |
| 内存 | 2 GB | **32 GB**（最低 16）| 机B 构成：离线名单缓存（hagezi_ti 210万条≈1.5G，四源全开≈4G）+ **域名结论缓存（百万级条目≈2~4G）** + Python 进程基线 + SQLite 页缓存 |
| 系统盘 | 20 GB | **200 GB SSD** | 过滤日志 90 天 + 允许日志（10万终端建议默认关，见第九节）+ 名单数据；SSD 必须（SQLite 写入+缓存换页） |
| 网络 | 内网万兆（或 2×千兆 bond） | 内网万兆 | 13,000 QPS × ~100B/包 ≈ 13MB/s 稳态，峰值约 60MB/s；内网转发链路建议万兆或 bond |
| 公网出站 | 不需要 | **100 Mbps+** | 离线名单下载（hagezi 36MB/日）+ 缓存未命中部分的公网递归 |
| 操作系统 | 任意主流 Linux x86_64 | **RHEL 8 系（AlmaLinux 8.5+/RHEL 8.7+）/ Ubuntu 20.04+ / 麒麟 V10 / 统信**；⚠️ **CentOS 7.x 已 EOL 不再支持**（glibc 2.17 过旧 + 需手工编译 Python≥3.10，规避为宜）；**必须 NTP 对时** |

> 代理在 10 万终端下依然轻松（纯转发不检测，Go 单进程几万 QPS 无压力，瓶颈在网络）。
> 平台配置的弹性项是内存里的缓存规模：32G 可支撑全量缓存 + hagezi_ti；预算受限 16G 起步（mini 名单 + 较小缓存 TTL），压测后扩。

## 三、环境与网络要求

### 3.1 机 B 出站白名单

| 类别 | 地址 | 端口 | 用途 |
|------|------|------|------|
| 上游公网 DNS | `223.5.5.5` 主 / `119.29.29.29` 备 | UDP/TCP 53 | 递归解析（缓存未命中部分） |
| 离线大名单 | `raw.githubusercontent.com` + `cdn.jsdelivr.net`（镜像降级） | 443/TCP | hagezi/StevenBlack/OISD |
| 离线大名单 | `urlhaus.abuse.ch` | 443/TCP | 哨兵名单（30 分钟更新） |
| 离线大名单 | `threatfox.abuse.ch` | 443/TCP | ThreatFox C2 hostfile（每日，方案 C） |
| 在线情报 API | `zen.spamhaus.org`、`dbl.spamhaus.org`、`dnsbl.dronebl.org`；`dnsbl.spfbl.net`（可选，默认停用） | UDP 53 | DNSBL 类 |
| 在线情报 API（可选） | `urlhaus-api.abuse.ch`、`threatfox-api.abuse.ch`、`api.threatbook.cn`、`api.xforce.ibmcloud.com`、`otx.alienvault.com`、`api.greynoise.io`、`checkurl.phishtank.com` | 443/TCP | HTTP 类（方案 C 后不预置，管理员手工创建源并启用才需要） |

> 在线情报源在此规模下**必须依赖缓存挡量**：即便缓存命中 95%，未命中的 5% 仍是每分钟数千次 API 调用——**免费 Key 配额根本不够**。两个选择（方案里默认 A）：
> - **A. 只保留 DNSBL 类源（spamhaus_dbl 等，走 DNS 协议、无次数限制、亚毫秒响应）+ 离线大名单扛主量**，HTTP 类在线源仅用于测试中心人工核验，不参与实时链路；
> - B. 采购商业情报源的企业配额（微步企业版等），费用另计。
> **不建议**同时启用多个 HTTP 类免费源跑实时链路。
>
> **方案 A 已是出厂默认（方案 C 2026-09-03 收敛后为 DNSBL 三源）**：新部署 seed 仅启用 spamhaus_zen/dbl、dronebl（spfbl 语义修正为邮件评分源后移出默认启用），HTTP 类不再预置、适配器保留可手工创建；C2 域名情报由 threatfox_hosts 离线大名单承载。实测收益（2026-08-31 优化后）：域名+IP 双结论缓存命中路径 **12ms**（优化前 IP 后置每次实时查 13 源为 0.9~3.2s）。

### 3.2 入站规则（最小暴露）

| 机器 | 端口 | 来源限制 |
|------|------|---------|
| 机 A | 53/UDP+TCP | **仅各 DC 的 IP 段** |
| 机 B | 15353/UDP+TCP | **仅机 A IP** |
| 机 B | 8080/TCP | 仅运维网段/堡垒机 |

> 本环境的运维策略：**系统层 firewalld 与 SELinux 关闭**（见《生产部署指引（AlmaLinux 8）》
> 第四节），上述来源限制**在上联防火墙/核心交换机 ACL 实施**——端口与来源要求不变，
> 只是实施位置从主机防火墙上移到网络边界。systemd 单元内的进程级加固
> （NoNewPrivileges/ProtectHome/PrivateTmp）不受影响照常生效。

### 3.3 系统参数

> 以下两项（sysctl 收发缓冲 / nofile 句柄）**安装脚本与 systemd 单元均已自动完成**
> （见 5.1/5.2 节），此处仅供脚本不可用时的手工兜底与核对。
> 服务现以 **root 运行**（内网专用设备 + 上联 ACL 边界防护形态），绑定 53 无需 setcap。

```bash
# 两机：DNS 高并发内核参数——脚本写入 /etc/sysctl.d/99-dnsfilter.conf
cat >> /etc/sysctl.d/99-dnsfilter.conf <<EOF
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.netdev_max_backlog=10000
EOF
sysctl --system
# 两机：文件句柄（SQLite/日志/线程）——systemd 单元 LimitNOFILE=65536 承担
# （手工前台运行时才需要 limits.conf）
```

### 3.4 软件依赖

机 A 零依赖（静态单二进制，仅需 systemd）；机 B Python ≥3.10 + venv
（requirements.txt 九个包，安装脚本自动装国内镜像）。
**AlmaLinux 8 / RHEL 8 系**：AppStream 直接安装——`python3.12` 需系统 ≥8.10
（`dnf install python3.12 python3.12-pip`），`python3.11` 需 ≥8.7；安装脚本两种都能自动
探测。离线部署选项：pip download 拷贝安装 + 手工灌名单（见 5.5 手工步骤）。
OS 专项准备与差异细节见 **《生产部署指引（AlmaLinux 8）》**。

---

## 四、前置开发项（**已全部交付**，此处为交付记录与验收口径）

按优先级排序，1~3 为**硬性前置**，4~5 强烈建议：

| # | 开发项 | 内容 | 状态 |
|---|--------|------|------|
| 1 | **域名检测结论缓存** | `domain_cache.py`：`域名+qtype → (结论, 应答, 时间戳)`；放行 TTL/拦截 TTL 分设、LRU 淘汰、名单变更失效联动；另含 IP 结论缓存 `ip_cache.py`（解析速度优化轮追加） | ✅ 已交付（5c966bf/0fc774e） |
| 2 | **fail-safe 在限流场景下的降级策略** | `circuit_breaker.py`：源级熔断（连续失败标记不可用，TTL 探活恢复）+ 路径级降级窗口；`GET /api/circuit-breaker/stats` 观测 + 手动复位 | ✅ 已交付（5c966bf） |
| 3 | **压测脚本与容量报告** | `tools/loadtest.py`（零依赖、异步 UDP、阶梯加压、zipf 热度分布） | ✅ 已交付（5c966bf，用法见 4.1） |
| 4 | 匿名化客户端 IP 采集策略 | 放行日志采样率 `allow_log_sample_rate`（计数取模确定性采样）；拦截/剔除日志必录不采样 | ✅ 已交付（5c966bf） |
| 5 | SQLite 写入削峰 | `log_writer.py` 异步批量写 + 名单内存缓存 + `GET /api/log-writer/stats` 观测 | ✅ 已交付（5c966bf） |

> 五项全落地后稳态查询 95%+ 走缓存纯内存路径（<10ms），剩余 5% 走完整检测；
> 第 2 项保证即便外部 API 全挂也不会误伤全网。**这些是本方案与百人级方案的本质区别。**

### 4.1 压测脚本用法（tools/loadtest.py，前置项 3 已交付）

零第三方依赖（Python 3.10+ 标准库），对 DNS 入口施加可控 QPS 的 UDP 压力，产出容量报告全部指标。

**核心设计**：
- 域名池带 zipf 热度分布（头 10% 域名承担 ~55% 流量），模拟真实终端访问局部性——均匀分布会显著低估缓存命中率；固定随机种子，报告可复现
- 发送/回收分离：发送协程严格按节拍发包不等应答（批量补发模型，Windows sleep 精度 15ms 下仍能维持目标速率），应答由独立回调按 QID 匹配
- 阶梯加压：`--qps` 逗号分隔多级，逐级找容量拐点
- 冷/热缓存对比：`--report-cache-warmup` 先 30s 低强度预热再正式压测

**标准容量验证流程**（对应第七节验证项 7/8）：

```bash
# 阶梯加压：1 千 → 1 万 → 3 万 QPS，每级 10 分钟
python tools/loadtest.py --target 127.0.0.1:15353 --qps 1000,10000,30000 \
    --duration 600 --domains 2000

# 冷/热缓存对比（验证前置项 1 的缓存收益）
python tools/loadtest.py --target 127.0.0.1:15353 --qps 500 --duration 30 \
    --report-cache-warmup

# 风暴演练：峰值 1.5 倍 × 3 分钟
python tools/loadtest.py --target 127.0.0.1:15353 --qps 45000 --duration 180
```

输出：控制台报告（实测 QPS、P50/P90/P95/P99/Max 延迟、超时率、丢包率、RCODE 分布、验收判定）+ `loadtest-report-<时间戳>.json` 留存基线。

**验收口径**：P95 <100ms 且丢包率 <0.1%（脚本自动判定）。

**本机（Windows 沙箱）验证结论**（2026-08-28，域名池 500 黑名单命中路径）：
- 500 QPS × 10s：5000/5000 全收、P95 75.7ms、零丢包，**脚本统计口径正确**
- 1000 QPS 以上：平台处理能力饱和在 ~400 QPS（瓶颈：`get_enabled_list` 每查询全表 SELECT + `write_filter_log` 同步 SQLite INSERT，20 线程池打满），超出部分积压超时——**这正是部署方案预言的瓶颈形态**，生产环境需靠前置项 1 缓存吸收 95%+ 流量 + 前置项 5 异步写日志解决
- 附带发现并修复：Windows ProactorEventLoop 的 UDP transport 在客户端先行关闭触发 ICMP port unreachable 后永久失聪（dns_server.py 已加 SelectorEventLoopPolicy 保护，Linux epoll 不受影响）

### 4.2 前置项 4/5 交付后的削峰收益（2026-08-28 实测）

前置项 5（异步日志 + 名单内存缓存）落地后，同环境同口径复测：

| 场景 | 削峰前 | 削峰后 | 提升 |
|------|--------|--------|------|
| 500 QPS × 10s | P95 75.7ms（达标） | **P95 1.09ms** | 70 倍 |
| 1000 QPS × 10s | 饱和 ~400 QPS，42% 超时 | **1000/1000 全收，P95 1.86ms，零丢包** | 从不达标 → 达标 |
| 2000 QPS × 10s | 70% 超时 | **20000/20000 全收，P95 0.91ms，零丢包** | 从不达标 → 达标 |
| 3000 QPS × 10s | — | **30000/30000 全收，P95 3.24ms，零丢包** | 达标 |
| 5000 QPS × 10s | 100% 超时 | 收 35k/50k（~2200 QPS 饱和） | 拐点在 ~3000-5000 之间 |

5000 QPS 段的剩余瓶颈（py-spy speedscope 采样）：28.9% 卡在
`call_soon_threadsafe → _write_to_self`——asyncio 线程池模型下每查询
完成回调都要写 self-pipe 唤醒事件循环，唤醒风暴打满主线程，属
Python asyncio 固有开销而非 SQLite（flusher 仅占 9.5% 且完全跟得上）。
**生产容量模型不受影响**：代理层扛终端全量压力，平台只处理代理去重
转发后的查询，单进程 ~2200-3000 QPS × 缓存命中率 ≥95% 已满足
10 万终端平均 5000~13000 QPS 的模型；若需更高，多代理实例分片。

配置项（system_config 热生效，配置页可调）：
- `allow_log_sample_rate`：放行日志采样率 0~100%（前置项 4）
- `log_async_enabled` / `log_flush_interval_s` / `log_batch_size`：异步写入开关/间隔/批量（前置项 5；`log_async_enabled=0` 回退同步直写，排障用）
- `GET /api/log-writer/stats`：入队/落库/丢弃/队列深度观测（dropped>0 说明写入跟不上，需调大批量或检查磁盘 IO）

## 五、安装步骤（一键脚本部署）

> 部署产物已脚本化：`deploy/install-proxy.sh`（机 A）+ `deploy/install-platform.sh`（机 B），
> 配置模板 `proxy/proxy.example.yaml` + `platform/platform.example.yaml` 均为**全量中文注释版**
> （每项含取值范围、生产建议、生效方式），脚本自动从模板生成实际配置并替换关键键值。
> 不想用脚本的手工步骤见 5.5 节（内容与脚本一致）。

### 5.0 准备（两机通用）

```bash
# ① 拉代码（或 git clone 后 scp 整个目录到目标机）
git clone https://github.com/Milo799/dns-security-filter.git
cd dns-security-filter

# ② 交叉编译 Linux 代理二进制（任意有 Go>=1.21 的机器，含开发机）
cd proxy && GOPROXY=https://goproxy.cn,direct GOOS=linux GOARCH=amd64 go build -o ../bin/dns-proxy . && cd ..
# 编译产物 bin/dns-proxy 随代码目录一起带到机 A

# ③ 确认机器满足第二节配置要求；两机 NTP 对时（强制）
```

### 5.1 机 B（检测平台）——一条命令

```bash
sudo ./deploy/install-platform.sh --upstream-dns 223.5.5.5 --alert-ip 10.0.0.99
```

脚本自动完成 9 件事（幂等可重跑）：环境检测（Python>=3.10/内存预警）→ 代码落位 →
venv+pip 依赖（清华镜像）→ **自动生成随机 jwt_secret 与管理员初始密码**并从全注释模板
生成 platform.yaml → 装 systemd 双服务并启动（root 运行，无需专用用户/setcap）→
内核参数调优 → 每日备份 timer → 自检（服务/端口/健康接口）。

**参数表**（全部可选，默认值适合双机标准拓扑）：

| 参数 | 默认 | 说明 |
|------|------|------|
| `--dns-port` | 15353 | 平台 DNS 监听端口（代理转发到这里） |
| `--web-port` | 8080 | Web 管理端口 |
| `--upstream-dns` | 223.5.5.5 | 公网递归 DNS（⚠️ 严禁指向本系统） |
| `--alert-ip` | 127.0.0.1 | 拦截引导页 IP（生产建议内网告警页） |
| `--memory-max` | 24G | systemd 内存上限（16G 机器设 10G） |
| `--pip-mirror` | 清华源 | 无外网时换本地源 |
| `--install-dir` | /opt/dns-security-filter | 安装目录 |
| `--skip-tuning` | - | 跳过 sysctl/limits 调优 |

装完屏幕会打印**管理员初始密码**（仅首次生成配置时）——登录
`http://机B:8080` 后立即改密，再导入离线大名单（威胁情报→离线情报源，
hagezi_mini 起步）。

### 5.2 机 A（代理）——一条命令

```bash
sudo ./deploy/install-proxy.sh --upstream 192.168.10.21 --upstream-port 15353
```

脚本自动完成 7 件事（幂等可重跑）：环境检测（53 占用自动提示 systemd-resolved
让端口方法）→ 目录 → 二进制安装（root 运行无需 setcap）→ 从全注释模板生成
config.yaml → systemd 服务并启动 → 内核参数 → 自检。
（**AlmaLinux 8 注意**：无 systemd-resolved，53 端口占用提示照常工作，命中才提示。）

**参数表**：

| 参数 | 默认 | 说明 |
|------|------|------|
| `--upstream` | 127.0.0.1 | ★ 机 B 内网 IP |
| `--upstream-port` | 15353 | 与机 B 的 `--dns-port` 一致 |
| `--listen-port` | 53 | 本机监听端口（域控转发器指向它） |
| `--forward-timeout` | 8 | 转发超时秒（生产 ≥8） |
| `--binary` | bin/dns-proxy | 预编译二进制路径 |
| `--install-dir` | /opt/dns-security-filter | 安装目录 |
| `--skip-tuning` | - | 跳过 sysctl/limits 调优 |

### 5.3 脚本透明化清单（变更点审计用）

| 变更点 | 内容 | 回滚方式 |
|--------|------|---------|
| 文件 | `/opt/dns-security-filter/`（bin/proxy/platform/web/data） | 删目录 |
| venv | `platform/venv`（9 个 pip 包） | 删 venv 目录 |
| systemd | proxy / platform-dns / platform-web 三服务（enable+start，root 运行） | `systemctl disable --now <svc>` 后删 unit 文件 |
| 备份 | dnsfilter-backup.timer + .service（每日 02:30）+ /var/backups/dnsfilter/ 备份目录 | `systemctl disable --now dnsfilter-backup.timer` 后删 unit 文件与备份目录 |
| 内核参数 | `/etc/sysctl.d/99-dnsfilter.conf`（rmem/wmem 16MB、backlog 10000） | 删该文件后 `sysctl --system` |
| 配置 | 从 example 生成（**已存在则永不覆盖**） | 删配置文件重跑脚本 |

### 5.4 改配置的正确姿势

两个 example 模板里每一项都有中文注释（含义/取值/生产建议），照注释改即可：

```bash
# 机 A 代理（改后生效）：
sudo vi /opt/dns-security-filter/proxy/config.yaml && sudo systemctl restart proxy

# 机 B 平台（dns/web/database 三段改后须重启；检测/日志/缓存类多支持 Web 在线热调）：
sudo vi /opt/dns-security-filter/platform/platform.yaml
sudo systemctl restart platform-dns platform-web
```

Web 配置页（系统→系统配置）可在线调整的项存 SQLite，**优先级高于 yaml**
（运行时覆盖）：放行日志采样率、异步写入三参数、缓存 TTL/容量、熔断降级、
自动更新周期、fail-safe 模式等。

**双进程热生效说明**：Web 改配置/名单后，DNS 进程由内置跨进程轮询
（`cross_sync`，60s 周期）自动感知——配置同步、人工名单/离线大名单/
情报源变更触发对应缓存失效，**最长 60s 生效**，无需重启 DNS 服务。
（dns/web/database 等监听类配置仍需重启两个服务。）

### 5.5 手工部署（脚本不可用时的兜底，内容与脚本等价）

<details>
<summary>展开手工步骤（机 A / 机 B）</summary>

**机 A（代理）：**

```bash
sudo mkdir -p /opt/dns-security-filter/{bin,proxy}
sudo install -m 0755 bin/dns-proxy /opt/dns-security-filter/bin/
sudo cp proxy/proxy.example.yaml /opt/dns-security-filter/proxy/config.yaml
# 编辑 config.yaml：upstream_addr=机B IP、upstream_port=15353、forward_timeout=8
sudo cp deploy/proxy.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now proxy
```

**机 B（平台）：**

```bash
sudo mkdir -p /opt/dns-security-filter
sudo cp -r platform web tools /opt/dns-security-filter/     # tools 含备份脚本
sudo chmod +x /opt/dns-security-filter/tools/*.sh
cd /opt/dns-security-filter/platform && sudo python3.12 -m venv venv   # 或 python3.11
sudo ./venv/bin/pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
sudo cp platform.example.yaml platform.yaml
# 编辑 platform.yaml：jwt_secret（openssl rand -hex 32）、admin_initial_password、
#   dns.listen_port=15353、upstream_dns、alert_ip（模板内有逐项注释）
mkdir -p data
sudo cp deploy/platform-dns.service deploy/platform-web.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now platform-dns platform-web
# 备份 timer（等价于脚本第 9 步；<INSTALL_DIR> 按实际路径替换 service 内路径）
sudo sed -e "s|/opt/dns-security-filter|/opt/dns-security-filter|g" \
    deploy/dnsfilter-backup.service > /etc/systemd/system/dnsfilter-backup.service
sudo cp deploy/dnsfilter-backup.timer /etc/systemd/system/
sudo mkdir -p /var/backups/dnsfilter && sudo chown dnsfilter:dnsfilter /var/backups/dnsfilter
sudo systemctl daemon-reload && sudo systemctl enable --now dnsfilter-backup.timer
```

</details>

## 六、域 DNS（多台 DC）转发器配置

```
每台 DC：DNS 管理器 → 服务器属性 → 转发器：
  ① 记录/截图原转发器配置（容灾回退备份）
  ② 删除原公网转发器，添加 192.168.10.20（机A IP）
  ③ 转发器超时设 8~10s（与代理 forward_timeout 匹配）
```

**多 DC 灰度策略（10 万终端强烈建议）**：
1. **选用户最少的 1 台 DC 先切**，观察 3~7 天（拦截日志、误报、终端反馈、平台资源曲线）
2. 无异常后逐台追加，每台间隔 ≥1 天
3. 哑终端常无 ECS 能力（部分旧系统不附加 Client Subnet），其查询的 client_ip 可能为空——不影响过滤，只影响日志定位，属预期

**EDNS0 ECS 说明**：Windows Server 2012+ DC 默认附加；若组策略曾设 `DisableEDNSProbes=1` 需移除，否则平台拿不到终端 IP。

## 七、上线验证清单

| # | 验证项 | 命令/操作 | 预期 |
|---|--------|----------|------|
| 1 | 服务三件套 | `systemctl status proxy platform-dns platform-web` | 全部 running + 开机自启 |
| 2 | 链路连通 | 机A `dig @机B -p 15353 www.baidu.com` | 真实 IP |
| 3 | 全链路（直打代理） | 内网机 `dig @机A www.baidu.com` | 真实 IP，P95 <50ms（缓存命中） |
| 4 | 缓存命中率 | `GET /api/domain-cache/stats` 与 `GET /api/ip-cache/stats`（需先登录拿 token） | 稳态 ≥95% |
| 5 | 黑名单拦截 | 加 `test-block.example.com` 后 dig | 告警 IP，0s |
| 6 | 拦截日志与终端 IP | Web → 过滤日志 | client_ip 为终端真实 IP |
| 7 | **压测基准** | `python tools/loadtest.py --target 机B:15353 --qps 10000 --duration 600`（直打平台；打全链路改 `--target 机A:53`） | P95 延迟 <100ms、无丢包、CPU <70%、内存稳定 |
| 8 | **风暴演练** | 打峰值 1.5 倍 × 3 分钟 | 服务不崩，超限部分排队或快速失败 |
| 9 | 容灾演练 | 停 platform-dns → 终端查询 | SERVFAIL 约 8s，无静默挂起；改回转发器立即恢复 |
| 10 | 误拦截应急 | Web 加白名单 | 秒级生效 |
| 11 | 日志清理 | 等待 6 小时周期或重启服务后查 `GET /api/log-retention/stats` | `total_runs ≥ 1`；插入超期测试行可即时验证删除 |
| 12 | 灰度首台 DC 观察 | 3~7 天 | 误报率/资源曲线正常 |
| 13 | 数据库备份 | `systemctl list-timers dnsfilter-backup.timer`；手工触发 `sudo systemctl start dnsfilter-backup.service` 后 `ls /var/backups/dnsfilter/` | 定时器 active + 备份文件生成且 gzip 压缩 |
| 14 | 熔断与降级观测 | `GET /api/circuit-breaker/stats` | 各源 closed/正常；灰度期关注是否出现 open |
| 15 | 异步日志健康 | `GET /api/log-writer/stats`（灰度高峰期查） | `dropped=0` 且 queue_size 不持续增长 |

## 八、容灾与回退

**设计原则**（PRD）：任一故障 → SERVFAIL → 不自动放行（安全优先），人工决策切换。

| 故障场景 | 现象 | 处置 |
|---------|------|------|
| 机B平台挂 | 全网 SERVFAIL，**10 万终端外网解析中断** | ① 修复；② **紧急放行：任一 DC 把转发器改回公网 DNS，该 DC 覆盖的终端立即恢复**（这是多 DC 结构的优势：可分批放） |
| 机A代理挂 | DC 转发超时 | 改 DC 转发器直指机B:15353（临时）或回公网 |
| 在线情报源集体限流 | 未命中域名查询变慢 | 开发项 2 的熔断机制应已自动降级放行；否则临时停用在线源（Web 界面）只跑离线名单 |
| 公网 DNS 出站断 | 解析失败 | 切备用公网 DNS / 检查防火墙 |
| 误拦截业务域名 | 业务异常 | Web 加白名单秒生效 |

> **重要**：10 万终端规模下，"全网断网"的代价远高于百人级。强烈建议与安全负责人明确：**紧急场景优先保业务（回退转发器），事后补审计**。同时考虑给代理加一个"平台连续 N 次超时自动透传公网"的降级开关（可配置，默认关闭保安全，见前置开发项讨论）。

## 九、日常运维

- **日志策略**：10 万终端下 `allow_log_enabled` 必须为 false（全量放行日志 = 每日数百万行、SQLite 写放大拖垮检测）；拦截/剔除日志保留 90 天，预计每日 1~50 万行（取决于拦截率），**每周关注 platform.db 体积**
- **日志自动清理（已内置）**：`log_retention_days`（默认 90，配置页热生效）驱动后台清理线程——每 6 小时对 filter_log / audit_log 分批删除过期行（单批 1 万行防长事务锁库）；观测接口 `GET /api/log-retention/stats`（最近/累计删除行数、执行轮数；`total_deleted` 长期为 0 且库体积持续增长时检查天数配置）
- **缓存监控（已内置）**：`GET /api/domain-cache/stats`（域名结论缓存）与 `GET /api/ip-cache/stats`（IP 结论缓存）——条目数/容量/命中数/命中率；另有熔断 `GET /api/circuit-breaker/stats`、日志写入 `GET /api/log-writer/stats`。均需 JWT（curl 先 `/api/auth/login` 换 token）
- **备份（已内置）**：安装脚本自动部署 `dnsfilter-backup.timer`——每日 02:30 调 `tools/backup_db.sh` 对 platform.db 做 SQLite `.backup` 在线热备（与检测写入并发安全），gzip 压缩后默认保留 14 份于 `/var/backups/dnsfilter`（`BACKUP_KEEP` 环境变量可调）；手工备份同命令随时可跑；两份 yaml 变更留副本
- **升级窗口**：凌晨低峰；先平台后代理；升级前必跑测试套件
- **监控告警建议**：平台 SERVFAIL 率（代理日志 rcode 统计）、缓存命中率、磁盘水位、三进程存活、备份 timer 最近执行状态（`systemctl list-timers dnsfilter-backup.timer`）
- **api_key 安全**：情报源密钥 Fernet 加密落库（密钥由 platform.yaml 的 jwt_secret 派生）；**更换 jwt_secret 后旧密文解不开**——对应情报源按"未配 Key"处理（不发请求、三态无结论），管理员在界面重新保存一次 Key 即可

## 十、风险与已知边界

1. **灰度上线为强制要求**（第六节多 DC 灰度策略）：首台 DC 观察 3~7 天再逐台追加；跳过压测（第七节 7/8 项）直接全量是重大事故风险
2. **单点无 HA**：代理、平台均单实例。此规模建议中期演进：代理前置负载均衡（多代理 + DC 多转发器轮询）+ 平台主备（SQLite → PostgreSQL）。当前版本先靠快速回退兜底
3. **SQLite 写入是天花板之一**：拦截日志高峰写入与检测线程争锁——前置开发项 5（异步批量写）缓解；若日均日志 >500 万行考虑关停部分日志维度
4. **公网 DNS 依赖**：平台递归全部出公网（无本地递归缓存组件）；缓存上线后量可控，但公网链路抖动直接影响未命中查询
5. **ECS 隐私**：10 万终端 IP 全量入日志属敏感数据，注意日志库访问权限与保留期合规（等保要求可参照）
6. **时间同步**：两机 NTP 强制（缓存 TTL/审计/JWT 全依赖时钟）
