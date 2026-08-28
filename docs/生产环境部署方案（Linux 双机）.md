# 生产环境部署方案（Linux 双机）

> 适用场景：约 100 台内网终端，Windows 域环境，域控 DNS（DC）做转发器指向本系统代理。
> 拓扑：`终端(100) → Windows 域 DNS(转发器) → Go 代理(机A:53) → 检测平台(机B:53) → 公网 DNS`
> 编写基准：commit `e1bcade`（代理层已通过端到端验证：放行/拦截/SERVFAIL 容灾/EDNS0 透传）。

---

## 一、部署拓扑

```
                      ┌────────────────────────────────────────────┐
                      │                机 B（检测平台）              │
 ┌─────────┐   UDP53  │  ┌──────────────┐  UDP53   ┌────────────┐  │  UDP53
 │ 终端×100 │─────────▶│  │ 机 A（代理）  │─────────▶│ DNS 服务    │──┼────────▶ 公网 DNS
 └─────────┘          │  │ dns-proxy    │          │ dns_server │  │        223.5.5.5
                      │  │ :53 纯转发    │          │ :15353*    │  │        8.8.8.8 备用
                      │  └──────────────┘          ├────────────┤  │
                      │                            │ Web 管理    │  │
                      │                            │ uvicorn:8080│  │
                      │                            │ SQLite 数据 │  │
                      │                            └────────────┘  │
                      └────────────────────────────────────────────┘
   * 平台 DNS 服务监听端口可自定（生产建议 1053 避免与常见服务冲突），
     代理 upstream_port 与之对应即可；两机间通信走内网。

数据流：终端查询 → DC 转发器（附加 EDNS0 Client Subnet）→ 机A 代理原样透传 →
        机B 平台五层检测（白名单→黑名单→离线名单→在线情报→IP后置）→
        公网解析 → 应答原路返回。拦截时终端收到告警 IP（A）/空应答（AAAA）。
```

**职责划分**：
- **机 A（代理）**：Go 单二进制，纯转发不落盘，仅消耗网络与少量内存。故障时回 SERVFAIL。
- **机 B（平台）**：检测主流程 + Web 管理 + SQLite。内存大头是离线大名单缓存。

---

## 二、机器配置要求

| 项目 | 机 A（代理） | 机 B（平台） | 说明 |
|------|-------------|-------------|------|
| CPU | 2 vCPU | 4 vCPU | 机B 需并发情报源查询（线程池）+ SQLite 写入 |
| 内存 | 1 GB | 8 GB | 机B 内存大头：离线大名单缓存（hagezi_ti 210万条≈1.5GB；hagezi_mini 17万条≈120MB）|
| 系统盘 | 20 GB | 50 GB | 机B 需存离线名单导入数据 + 过滤日志（90 天保留）|
| 操作系统 | 任意主流 Linux（x86_64）| 同左 | CentOS 7.9+/Ubuntu 20.04+/RHEL 8+/麒麟/统信均可 |
| 网络 | 内网千兆 | 内网千兆 | 两机间 UDP 53 通信；机B 需公网出站 |
| 公网 | 不需要 | **必须** | 离线名单下载 + 在线情报 API + 公网 DNS 递归 |

> 100 终端规模下代理负载极低（DNS 查询 QPS 通常 < 10），机 A 配置无压力；
> 机 B 内存按所选离线名单档位调整：只开 hagezi_mini 时 4GB 即可，开 hagezi_ti 建议 8GB。

## 三、环境与网络要求

### 3.1 机 B 出站白名单（防火墙/安全组）

| 类别 | 地址 | 端口 | 用途 |
|------|------|------|------|
| 上游公网 DNS | `223.5.5.5`（主）/ `119.29.29.29` 或 `8.8.8.8`（备） | UDP/TCP 53 | 外网域名递归解析 |
| 离线大名单 | `raw.githubusercontent.com` | 443/TCP | hagezi/StevenBlack/OISD 主地址 |
| 离线大名单镜像 | `cdn.jsdelivr.net` | 443/TCP | GitHub raw 不可达时自动降级 |
| 离线大名单 | `urlhaus.abuse.ch` | 443/TCP | URLhaus 哨兵名单（30 分钟更新） |
| 在线情报 API（按启用的源逐项开） | `zen.spamhaus.org`/`dbl.spamhaus.org`、`dnsbl.dronebl.org`、`dnsbl.spfbl.net` | UDP 53 | DNSBL 类查询 |
| 在线情报 API | `urlhaus-api.abuse.ch`（需 Auth-Key）、`threatfox-api.abuse.ch`、`api.threatbook.cn`、`api.xforce.ibmcloud.com`、`otx.alienvault.com`、`api.greynoise.io`、`checkurl.phishtank.com` | 443/TCP | HTTP 类在线情报 |

> **最小开通集**（只用离线大名单场景）：`223.5.5.5:53` + `raw.githubusercontent.com` + `cdn.jsdelivr.net` + `urlhaus.abuse.ch`（均 443）。
> 启用在线情报源时按上表逐项添加；启用越多，单查询耗时与外部依赖越多，建议初期只开 2~3 个高价值源（如 spamhaus_dbl + 微步）。

### 3.2 入站规则

| 机器 | 端口 | 来源限制 |
|------|------|---------|
| 机 A | 53/UDP+TCP | **仅 Windows DC IP**（缩小暴露面） |
| 机 B | 15353（或自定）/UDP+TCP | **仅机 A IP** |
| 机 B | 8080/TCP（Web 管理） | 仅运维网段/堡垒机 |

### 3.3 系统参数（机 A + 机 B）

```bash
# 1) 端口授权：dnsfilter 用户绑定 53（低于1024特权端口）
sudo setcap 'cap_net_bind_service=+ep' /opt/dns-security-filter/bin/dns-proxy   # 机A
# 平台若直接绑 53 同理授权 python；监听 1053+ 则无需

# 2) DNS 负载相关内核参数（可选，100终端规模非必需）
net.core.rmem_max=4194304
net.core.wmem_max=4194304
```

### 3.4 软件依赖

| 机器 | 依赖 | 版本 | 说明 |
|------|------|------|------|
| 机 A | 无（静态编译单二进制） | — | 构建期才需 Go ≥1.21（可在任一有 Go 的机器交叉编译后拷贝二进制） |
| 机 B | Python | ≥ 3.10 | 系统自带或安装；3.12 已验证 |
| 机 B | pip 依赖 | 见 requirements.txt | dnslib/fastapi/uvicorn/PyJWT/bcrypt/pyyaml/requests/httpx（建议国内 pip 源） |
| 机 B | SQLite | 系统自带 | 无需独立部署 |

> **离线部署选项**：机 B 无法公网时，可在有网机器 `pip download -r requirements.txt -d pkgs/` 后拷贝内网安装；
> 离线大名单初始导入也可在能上网的机器上导出 CSV，从 Web 管理台"人工情报源 → 批量导入"手动灌入（之后无自动更新）。

---

## 四、安装步骤

### 4.0 前置：在能上网的机器构建代理二进制

```bash
git clone https://github.com/Milo799/dns-security-filter.git
cd dns-security-filter/proxy
export GOPROXY=https://goproxy.cn,direct
go build -o ../bin/dns-proxy .
# Linux 交叉编译（如在 Windows/macOS 上构建）：
# GOOS=linux GOARCH=amd64 go build -o ../bin/dns-proxy .
scp bin/dns-proxy user@机A:/tmp/
```

### 4.1 机 A（代理）安装

```bash
# 1) 目录与用户
sudo useradd -r -s /usr/sbin/nologin dnsfilter
sudo mkdir -p /opt/dns-security-filter/{bin,proxy}
sudo cp /tmp/dns-proxy /opt/dns-security-filter/bin/

# 2) 端口授权
sudo setcap 'cap_net_bind_service=+ep' /opt/dns-security-filter/bin/dns-proxy

# 3) 配置（关键项已标注）
sudo tee /opt/dns-security-filter/proxy/config.yaml > /dev/null <<'EOF'
listen_addr: 0.0.0.0        # 接收 DC 转发
listen_port: 53
upstream_addr: 192.168.10.21   # ★ 机B 内网 IP
upstream_port: 15353           # ★ 与机B platform.yaml 的 dns.listen_port 一致
forward_timeout: 8              # ★ ≥8s：平台含并发情报查询+公网解析，实测 2~5s，留余量
log_enabled: true               # 建议开启，方便初期排障（QPS低日志量可忽略）
EOF
sudo chown -R dnsfilter:dnsfilter /opt/dns-security-filter

# 4) systemd 服务（仓库 deploy/proxy.service）
sudo cp deploy/proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now proxy
sudo systemctl status proxy    # 确认监听 0.0.0.0:53
```

### 4.2 机 B（平台）安装

```bash
# 1) 目录与用户
sudo useradd -r -s /usr/sbin/nologin dnsfilter 2>/dev/null || true
sudo mkdir -p /opt/dns-security-filter/platform
sudo cp -r platform web /opt/dns-security-filter/    # web 目录随平台走（uvicorn 静态挂载）

# 2) Python 依赖（建议 venv 隔离）
cd /opt/dns-security-filter/platform
sudo python3 -m venv venv
sudo ./venv/bin/pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 3) 配置（关键项已标注）
sudo tee /opt/dns-security-filter/platform/platform.yaml > /dev/null <<'EOF'
dns:
  listen_addr: 0.0.0.0      # 接收机A转发
  listen_port: 15353        # 与机A代理 upstream_port 一致
web:
  listen_addr: 0.0.0.0
  listen_port: 8080
  jwt_secret: ★生产请换32位以上随机串★
database: ./data/platform.db
upstream_dns: 223.5.5.5     # ★ 公网递归 DNS（勿指向代理自身，会成环）
alert_ip: 127.0.0.1         # ★ 拦截时返回的告警 IP（可改为内网引导页地址）
alert_ttl: 60
fusion_strategy: any
log_retention_days: 90
allow_log_enabled: false    # 100终端建议 false（放行日志量大）；需审计放行时再开
detection_enabled: true
api_timeout_ms: 2000
admin_initial_password: ★首启后立即改★
EOF
mkdir -p data && sudo chown -R dnsfilter:dnsfilter /opt/dns-security-filter

# 4) systemd 服务（两个：DNS 服务 + Web 管理）
sudo cp deploy/platform-dns.service deploy/platform-web.service /etc/systemd/system/
# 注意：service 内 ExecStart 的 python 路径改为 venv：
#   ExecStart=/opt/dns-security-filter/platform/venv/bin/python dns_server.py
#   ExecStart=/opt/dns-security-filter/platform/venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8080
sudo systemctl daemon-reload
sudo systemctl enable --now platform-dns platform-web
```

### 4.3 systemd service 修订要点（部署时逐项核对）

仓库现有 service 是骨架模板，生产落位需改 3 处：
1. `ExecStart` Python 路径 → venv 内 python（见上）
2. 机 B `platform-dns.service` 增加资源上限：`MemoryMax=6G`（防离线名单缓存把机器打爆）
3. `Restart=on-failure` + `RestartSec=5` 已有，保留（进程崩溃自动拉起）

---

## 五、Windows 域 DNS（DC）转发器配置

```
DNS 管理器 → 服务器名 → 属性 → 转发器：
  ① 先记录/截图原有转发器配置（备份，容灾回退用）
  ② 删除原有公网转发器
  ③ 添加：192.168.10.20（机A IP）
```

**要点**：
- DC 的转发器超时建议设 8~10s（与代理 forward_timeout 匹配，避免 DC 先超时重试）
- 若 DC 启用了"启用转发器上的 Netmask 排序"无需改动，不影响
- 多台 DC 逐台改（改完一台观察一天再改下一台更稳）
- **EDNS0 Client Subnet**：Windows Server 2012+ 的 DC 转发时默认附加 ECS，
  平台借此记录真实客户端 IP；若 GP 关闭了 ECS（`DisableEDNSProbes`），
  日志中 client_ip 会为空，过滤不受影响，仅失去终端定位能力

---

## 六、上线验证清单

| # | 验证项 | 命令/操作 | 预期 |
|---|--------|----------|------|
| 1 | 机A代理监听 | `ss -lunp \| grep :53` | dns-proxy 进程 |
| 2 | 机B平台监听 | `ss -lunp \| grep 15353` | python 进程 |
| 3 | 链路连通（机A→机B） | 机A上 `dig @192.168.10.21 -p 15353 www.baidu.com` | 返回真实 IP |
| 4 | 全链路（直打代理） | 任意内网机 `dig @192.168.10.20 www.baidu.com` | 返回真实 IP，2~5s |
| 5 | 黑名单拦截 | Web 管理台加黑名单 `test-block.example.com` → `dig` 该域名 | 返回 alert_ip，0s |
| 6 | 拦截日志 | Web → 过滤日志 | 含域名/原因/客户端 IP |
| 7 | 客户端 IP 提取 | 查看拦截日志 client_ip 字段 | 终端真实 IP（非 DC IP）|
| 8 | DC 转发生效 | 终端 `nslookup www.baidu.com` | 走默认 DNS（DC）解析成功 |
| 9 | 拦截端到端 | 终端 `nslookup test-block.example.com` | 告警 IP |
| 10 | 容灾演练 | 机B `systemctl stop platform-dns` → 终端查询 | SERVFAIL（约8s），不静默挂起 |
| 11 | 容灾恢复 | `systemctl start platform-dns` | 查询自动恢复 |
| 12 | 开机自启 | 两机 reboot | 三服务自动 running |

---

## 七、容灾与回退

**设计原则**（PRD）：检测平台或代理任一故障 → 代理回 SERVFAIL → 终端解析失败（不自动放行，安全优先）；人工决策后切换。

| 故障场景 | 现象 | 处置 |
|---------|------|------|
| 机B平台挂 | 代理回 SERVFAIL，终端外网解析失败 | ① 修平台；② 紧急放行：DC 转发器改回公网 DNS（备份配置），外网立即恢复（绕过过滤） |
| 机A代理挂 | DC 转发超时，终端解析失败 | 同上，改 DC 转发器直接指向机B:15353 亦可（临时） |
| 公网 DNS 出站断 | 平台解析失败回 SERVFAIL | 检查防火墙出站；或临时切备用公网 DNS |
| 误拦截（业务域名被拦） | 业务异常 | Web 管理台加白名单（秒生效）+ 删除错误黑名单条目 |

**回退操作**（保留在运维手册）：
```
紧急回退：DC DNS 管理器 → 转发器 → 改回原公网 DNS（如 223.5.5.5）
恢复过滤：转发器改回 机A IP
```

---

## 八、日常运维

- **日志保留**：`log_retention_days: 90`（过滤日志自动清理，SQLite 体积可控）
- **离线名单自动更新**：Web → 离线情报源（各源带下次更新倒计时）；建议初期只启 hagezi_mini（内存友好）+ urlhaus（30分钟哨兵）
- **备份**：`platform/data/platform.db` 每日备份（SQLite 单文件，停服或用 `.backup` 命令热备）；配置文件两份 yaml 变更时留副本
- **监控**：`systemctl status proxy platform-dns platform-web` 三服务；代理 `log_enabled: true` 时日志里有每查询的 rcode，SERVFAIL 突增=平台异常的早期信号
- **升级**：拉新代码 → 机A 重编译拷贝二进制 → 机B `git pull` + venv 依赖更新 → 逐台重启（先平台后代理）

---

## 九、风险与已知边界

1. **单点无高可用**：代理、平台均为单实例（PRD 明确无 HA 设计），故障靠人工回退（本方案第七节）。若未来要 HA：代理可多台 + DC 多转发器（轮询）；平台需解决 SQLite 单写者限制（换 PostgreSQL 或主备）。
2. **SERVFAIL 期间终端无外网解析**：这是安全优先的设计选择（不静默放行）；对可用性敏感可在 DC 加第二个转发器指向公网 DNS 作兜底（代价：故障时流量绕过过滤，需权衡）。
3. **放行日志默认关**：100 终端若全开 allow_log，日志表增长快（每天数万条）；需要终端行为审计时再临时开启。
4. **上游 DNS 成环风险**：`platform.yaml` 的 `upstream_dns` 绝不能指向本系统自身（代理或平台），否则解析死循环——部署时逐项核对。
5. **时间同步**：两机 NTP 对时（日志时序、JWT 鉴权、名单更新调度都依赖时钟）。
