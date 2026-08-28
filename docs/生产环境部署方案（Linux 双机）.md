# 生产环境部署方案（Linux 双机 · 10 万终端规模）

> 适用场景：约 **10 万终端**（PC/服务器/哑终端混合），Windows 域环境，多台域控 DNS（DC）做转发器指向本系统代理。
> 目标拓扑：`终端(10万) → 域 DNS 转发器(多台 DC) → Go 代理(机A:53) → 检测平台(机B) → 公网 DNS`
> 编写基准：commit `e1bcade`（端到端验证通过）+ 本方案第四节的**前置开发项**完成后方可上线。

---

## ⚠️ 零、先读这一节：当前架构在此规模下不可用，必须先开发再部署

10 万终端的负载测算（办公混合场景经验值）：

| 指标 | 数值 |
|------|------|
| 平均查询速率 | 每终端 3~8 查询/分钟 → **5,000~13,000 QPS** |
| 晨启风暴峰值（开机 30 分钟集中解析） | 平均值 × 5 → **约 30,000~60,000 QPS** |
| DNS 唯一域名集中度（10 万终端环境） | 常态约 200~500 万种域名，但**热点极集中**：Top 1 万域名覆盖 90%+ 查询量（CDN、门户、办公 SaaS、系统服务） |

当前代码的真实瓶颈（实测数据）：

| 环节 | 现状 | 在 10 万终端下会发生什么 |
|------|------|------------------------|
| 白/黑名单、离线大名单 | 内存 O(1)，<1ms | ✅ 不是瓶颈 |
| 在线情报源查询 | 每个未命中域名逐次调外部 API（并发 2s 超时） | ❌ **API 全部被限流（429/超时）**；三态语义 fail-safe 会把"无结论"判为**默认拦截** → **全网域名被拦 → 10 万终端断网** |
| 公网递归解析 | 每次查询都发上游（无缓存） | ❌ 上游 DNS 被打爆 / 出站带宽耗尽 |
| 平台线程池吞吐 | 单查询 0.4~2.5s × 池线程数 | ❌ 上限约 **20~100 QPS**，与需求差 2~3 个数量级 |

**结论：直接部署 = 上线即事故。** 必须先完成第四节的前置开发项（核心是**检测结论缓存 + 放行域名短 TTL 缓存**），把稳态查询处理压回"纯内存"路径，才能支撑这个规模。缓存命中后在线情报 API 调用量与公网解析量会下降 90%+（热点域名重复查询），各环节全部回到安全区间。

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
| 操作系统 | 任意主流 Linux x86_64 | 同左 | 内核 ≥4.x；CentOS 7.9+/Ubuntu 20.04+/麒麟/统信均可；**必须 NTP 对时** |

> 代理在 10 万终端下依然轻松（纯转发不检测，Go 单进程几万 QPS 无压力，瓶颈在网络）。
> 平台配置的弹性项是内存里的缓存规模：32G 可支撑全量缓存 + hagezi_ti；预算受限 16G 起步（mini 名单 + 较小缓存 TTL），压测后扩。

## 三、环境与网络要求

### 3.1 机 B 出站白名单

| 类别 | 地址 | 端口 | 用途 |
|------|------|------|------|
| 上游公网 DNS | `223.5.5.5` 主 / `119.29.29.29` 备 | UDP/TCP 53 | 递归解析（缓存未命中部分） |
| 离线大名单 | `raw.githubusercontent.com` + `cdn.jsdelivr.net`（镜像降级） | 443/TCP | hagezi/StevenBlack/OISD |
| 离线大名单 | `urlhaus.abuse.ch` | 443/TCP | 哨兵名单（30 分钟更新） |
| 在线情报 API | `zen.spamhaus.org`、`dbl.spamhaus.org`、`dnsbl.dronebl.org`、`dnsbl.spfbl.net` | UDP 53 | DNSBL 类 |
| 在线情报 API | `urlhaus-api.abuse.ch`、`threatfox-api.abuse.ch`、`api.threatbook.cn`、`api.xforce.ibmcloud.com`、`otx.alienvault.com`、`api.greynoise.io`、`checkurl.phishtank.com` | 443/TCP | HTTP 类（启用才开） |

> 在线情报源在此规模下**必须依赖缓存挡量**：即便缓存命中 95%，未命中的 5% 仍是每分钟数千次 API 调用——**免费 Key 配额根本不够**。两个选择（方案里默认 A）：
> - **A. 只保留 DNSBL 类源（spamhaus_dbl 等，走 DNS 协议、无次数限制、亚毫秒响应）+ 离线大名单扛主量**，HTTP 类在线源仅用于测试中心人工核验，不参与实时链路；
> - B. 采购商业情报源的企业配额（微步企业版等），费用另计。
> **不建议**同时启用多个 HTTP 类免费源跑实时链路。

### 3.2 入站规则（最小暴露）

| 机器 | 端口 | 来源限制 |
|------|------|---------|
| 机 A | 53/UDP+TCP | **仅各 DC 的 IP 段** |
| 机 B | 15353/UDP+TCP | **仅机 A IP** |
| 机 B | 8080/TCP | 仅运维网段/堡垒机 |

### 3.3 系统参数

```bash
# 机 A：端口授权（dnsfilter 用户绑 53）
sudo setcap 'cap_net_bind_service=+ep' /opt/dns-security-filter/bin/dns-proxy

# 机 B：若直接监听 53 需同样授权 python；监听 15353 无需
# 两机：DNS 高并发内核参数
cat >> /etc/sysctl.conf <<EOF
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.netdev_max_backlog=10000
EOF
sysctl -p
# 两机：文件句柄（SQLite/日志/线程）
echo 'dnsfilter soft nofile 65536' | sudo tee -a /etc/security/limits.conf
```

### 3.4 软件依赖

同前版：机 A 零依赖（静态单二进制）；机 B Python ≥3.10 + venv（requirements.txt 九个包，国内 pip 源）。离线部署选项同前（pip download 拷贝安装 + 手工灌名单）。

---

## 四、前置开发项（部署前必须完成，当前代码不支持此规模）

按优先级排序，1~3 为**硬性前置**，4~5 强烈建议：

| # | 开发项 | 内容 | 工作量 | 不做的后果 |
|---|--------|------|--------|-----------|
| 1 | **域名检测结论缓存** | process_query 增加内存缓存：`域名+qtype → (结论, 应答, 时间戳)`；放行结论 TTL 5~15 分钟、拦截结论 TTL 1 小时；容量上限 LRU 淘汰（如 100 万条）；名单变更时 invalidate | 中（含并发安全与失效逻辑，约 150 行 + 测试） | 平台吞吐上限约 100 QPS，10 万终端直接雪崩 |
| 2 | **fail-safe 在限流场景下的降级策略** | 在线情报源连续 N 次限流/超时 → 该源自动熔断（标记不可用，TTL 后探活恢复），无结论源不再触发"默认拦截"兜底，改为**放行并记日志**（或至少提供该开关） | 小（约 60 行） | 上线即全网断网（API 限流→全部无结论→全拦） |
| 3 | **压测脚本与容量报告** | dnsperf/flamethrower 对代理+平台打目标 QPS（先 1 千再 1 万再 3 万），出具 P95 延迟/丢包率/CPU/内存曲线，验证缓存命中率 ≥95% | 小（脚本+执行） | 配置拍脑袋，上线赌运气 |
| 4 | 匿名化客户端 IP 采集策略 | 10 万终端全量 client_ip 入日志，日志表每日百万行级——决定是否只记拦截+白名单（默认）或加采样 | 小（配置项） | 日志库膨胀、SQLite 写放大 |
| 5 | SQLite 写入削峰 | 拦截日志异步批量写（内存队列 + 定期 flush），避免高 QPS 下写锁竞争拖慢检测线程 | 中 | 峰值期日志写入拖慢应答 |

> 第 1、2 项完成后，稳态查询 95%+ 走缓存纯内存路径（<10ms），剩余 5% 走完整检测；第 2 项保证即便外部 API 全挂也不会误伤全网。**这三项是本方案与百人级方案的本质区别。**

## 五、安装步骤

### 5.0 构建代理二进制（任意有 Go ≥1.21 的机器）

```bash
git clone https://github.com/Milo799/dns-security-filter.git
cd dns-security-filter/proxy
export GOPROXY=https://goproxy.cn,direct
GOOS=linux GOARCH=amd64 go build -o ../bin/dns-proxy .
scp bin/dns-proxy user@机A:/tmp/
```

### 5.1 机 A（代理）

```bash
sudo useradd -r -s /usr/sbin/nologin dnsfilter
sudo mkdir -p /opt/dns-security-filter/{bin,proxy}
sudo cp /tmp/dns-proxy /opt/dns-security-filter/bin/
sudo setcap 'cap_net_bind_service=+ep' /opt/dns-security-filter/bin/dns-proxy

sudo tee /opt/dns-security-filter/proxy/config.yaml > /dev/null <<'EOF'
listen_addr: 0.0.0.0
listen_port: 53
upstream_addr: 192.168.10.21     # ★ 机B 内网 IP
upstream_port: 15353              # ★ 与机B platform.yaml dns.listen_port 一致
forward_timeout: 8               # ★ ≥8s（平台完整检测路径耗时上限余量）
log_enabled: false               # ★ 10万终端下代理逐查询日志量大，关闭（排障时临时开）
EOF
sudo chown -R dnsfilter:dnsfilter /opt/dns-security-filter

sudo cp deploy/proxy.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now proxy
```

### 5.2 机 B（平台）

```bash
sudo useradd -r -s /usr/sbin/nologin dnsfilter 2>/dev/null || true
sudo mkdir -p /opt/dns-security-filter
sudo cp -r platform web /opt/dns-security-filter/
cd /opt/dns-security-filter/platform
sudo python3 -m venv venv
sudo ./venv/bin/pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

sudo tee /opt/dns-security-filter/platform/platform.yaml > /dev/null <<'EOF'
dns:
  listen_addr: 0.0.0.0
  listen_port: 15353
web:
  listen_addr: 0.0.0.0
  listen_port: 8080
  jwt_secret: ★32位以上随机串★
database: ./data/platform.db
upstream_dns: 223.5.5.5          # ★ 公网递归；严禁指向本系统（成环）
alert_ip: ★建议内网告警引导页IP★
alert_ttl: 60
fusion_strategy: any
log_retention_days: 90
allow_log_enabled: false          # ★ 10万终端默认关（见第九节）
detection_enabled: true
api_timeout_ms: 2000
admin_initial_password: ★首启即改★
EOF
mkdir -p data && sudo chown -R dnsfilter:dnsfilter /opt/dns-security-filter

# systemd：service 模板需修订（ExecStart 改 venv python + 资源上限）
# platform-dns.service 增加：
#   MemoryMax=24G
#   LimitNOFILE=65536
sudo cp deploy/platform-dns.service deploy/platform-web.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now platform-dns platform-web
```

### 5.3 systemd service 修订要点（部署时逐项核对）

1. 两个平台 service 的 `ExecStart` python 路径改为 `/opt/dns-security-filter/platform/venv/bin/python`
2. `platform-dns.service` 加 `MemoryMax=24G`（防缓存把机器打爆，留 8G 系统余量）+ `LimitNOFILE=65536`
3. 保留 `Restart=on-failure`/`RestartSec=5`（崩溃自动拉起）

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
| 4 | 缓存命中率 | 平台日志/统计（开发项 3 的产物） | 稳态 ≥95% |
| 5 | 黑名单拦截 | 加 `test-block.example.com` 后 dig | 告警 IP，0s |
| 6 | 拦截日志与终端 IP | Web → 过滤日志 | client_ip 为终端真实 IP |
| 7 | **压测基准** | dnsperf 打 1 万 QPS × 10 分钟 | P95 延迟 <100ms、无丢包、CPU <70%、内存稳定 |
| 8 | **风暴演练** | 打峰值 1.5 倍 × 3 分钟 | 服务不崩，超限部分排队或快速失败 |
| 9 | 容灾演练 | 停 platform-dns → 终端查询 | SERVFAIL 约 8s，无静默挂起；改回转发器立即恢复 |
| 10 | 误拦截应急 | Web 加白名单 | 秒级生效 |
| 11 | 日志清理 | 检查 90 天自动清理 | 生效 |
| 12 | 灰度首台 DC 观察 | 3~7 天 | 误报率/资源曲线正常 |

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
- **缓存监控**：命中率、缓存条目数、LRU 淘汰率（开发项 1 的统计接口）
- **备份**：platform.db 每日备份（SQLite `.backup` 热备）；两份 yaml 变更留副本
- **升级窗口**：凌晨低峰；先平台后代理；升级前必跑测试套件
- **监控告警建议**：平台 SERVFAIL 率（代理日志 rcode 统计）、缓存命中率、磁盘水位、三进程存活

## 十、风险与已知边界

1. **前置开发未完成前禁止上线**（第零节+第四节）；跳过压测直接上 10 万终端是重大事故风险
2. **单点无 HA**：代理、平台均单实例。此规模建议中期演进：代理前置负载均衡（多代理 + DC 多转发器轮询）+ 平台主备（SQLite → PostgreSQL）。当前版本先靠快速回退兜底
3. **SQLite 写入是天花板之一**：拦截日志高峰写入与检测线程争锁——前置开发项 5（异步批量写）缓解；若日均日志 >500 万行考虑关停部分日志维度
4. **公网 DNS 依赖**：平台递归全部出公网（无本地递归缓存组件）；缓存上线后量可控，但公网链路抖动直接影响未命中查询
5. **ECS 隐私**：10 万终端 IP 全量入日志属敏感数据，注意日志库访问权限与保留期合规（等保要求可参照）
6. **时间同步**：两机 NTP 强制（缓存 TTL/审计/JWT 全依赖时钟）
