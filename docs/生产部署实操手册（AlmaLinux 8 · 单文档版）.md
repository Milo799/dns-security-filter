# 生产部署实操手册（AlmaLinux 8 · 单文档版）

> **本文档自包含**：从裸机到灰度上线只看这一份，按顺序执行即可，不需要在多份文档之间跳转。
>
> **环境基线（本文档按此编写）**：
> - 操作系统：AlmaLinux 8（8.5 出厂已 `dnf update`，python3.12 **已装好**）
> - 运维策略：系统层 **firewalld 与 SELinux 已关闭**，访问控制在上联防火墙/交换机实施
> - 拓扑：双机——机 A（代理，跑 dns-proxy）+ 机 B（检测平台，跑 platform-dns + platform-web）
> - 代码基准：commit `efce39d`（含全部生产就绪修复）
>
> 机器代号约定：下文用 **机A** 指代理机（接收域控转发的 DNS 查询）、**机B** 指平台机（检测决策 + Web 管理）。

---

## 一、整体架构与端口

```
终端(10万) → 域DNS转发器(多台DC) → 机A dns-proxy:53 → 机B 检测平台:15353 → 公网DNS 223.5.5.5
                                                          机B Web管理:8080（仅运维网段）
```

| 机器 | 角色 | 端口 | 系统上跑什么 |
|------|------|------|-------------|
| 机 A | 代理（纯转发） | 53/UDP+TCP | `proxy` 服务（静态 Go 二进制，零依赖） |
| 机 B | 检测平台 | 15353/UDP+TCP | `platform-dns` 服务（Python 3.12 + venv） |
| 机 B | Web 管理 | 8080/TCP | `platform-web` 服务（同上 venv） |
| — | 备份 | — | `dnsfilter-backup.timer` 每日 02:30 热备 SQLite |

两机安装目录统一为 `/opt/dns-security-filter/`（bin / proxy / platform / web / tools / data）。

## 二、部署前置检查（5 分钟）

在两机上各执行一遍，逐项确认：

```bash
# ① Python 3.12 三件套齐了吗（仅机 B 需要；昨日报错根因就是缺 pip 包）
python3.12 -V && python3.12 -m pip --version
#    任何一个报错 → dnf install -y python3.12 python3.12-pip python3.12-setuptools

# ② firewalld / SELinux 确认关闭
systemctl is-active firewalld   # 预期 inactive
getenforce                      # 预期 Disabled

# ③ NTP 对时（缓存 TTL/审计/JWT 全依赖时钟，强制项）
timedatectl status | grep -E 'NTP|synchronized'   # 预期 NTP service active + synchronized yes
#    未同步 → dnf install -y chrony && systemctl enable --now chronyd

# ④ 基础工具（脚本 rsync、自检 curl、验证 dig、备份 sqlite3）
dnf install -y rsync curl bind-utils sqlite

# ⑤ 机 B 出站连通（三种目的地都要通）
curl -sI -m 8 https://pypi.tuna.tsinghua.edu.cn/simple/ | head -1   # pip 镜像，预期 200
dig +short +time=3 @223.5.5.5 www.baidu.com                          # 公网递归，预期有 IP
dig +short +time=3 test.dbl.spamhaus.org.                            # DNSBL 链路（官方测试值，预期 127.0.1.2）
```

> 若 ⑤ 中 pip 镜像不通，改用 `--pip-mirror` 参数换内网源（见安装脚本参数表）；公网递归不通则整个方案不成立（平台解析依赖上游）。
> DNSBL 注意：`test.dbl.spamhaus.org` 查询**必须经 223.5.5.5 / 119.29.29.29 这类递归**——Spamhaus 会对 8.8.8.8 等超大型公共解析器限流（实测经 8.8.8.8 查官方测试值返回空应答）。平台 DNSBL 源默认 resolver 已配 223.5.5.5，与上游递归一致。

## 三、机 B（检测平台）安装

### 3.1 上传代码

把整个仓库目录（**必须含 `bin/dns-proxy`**，代理二进制已预编译好随包分发）上传到机 B 任意临时目录：

```bash
# 在你的办公机/跳板机上执行（示例，路径按实际改）
scp -r /path/to/dns-security-filter root@机B_IP:/root/
```

### 3.2 一条命令安装

```bash
cd /root/dns-security-filter
sudo bash ./deploy/install-platform.sh --upstream-dns 223.5.5.5 --alert-ip 10.0.0.99
```

脚本幂等可重跑，自动完成 9 件事：环境检测（Python≥3.10/pip 模块缺失提前告警/内存预警）→ 代码落位 /opt/dns-security-filter → venv + pip 依赖（清华镜像）→ **自动生成随机 jwt_secret 与管理员初始密码** → 装 systemd 双服务并启动 → 内核参数调优 → 每日备份 timer（02:30，保留 14 份）→ 自检（服务/端口/健康接口）。

> **运行形态**：全部服务以 root 运行（内网专用设备 + 上联 ACL 边界防护），不创建专用系统用户、无需 setcap 授权——从源头杜绝属主/属组类权限报错。如组织安全基线强制要求非特权用户运行，见 FAQ 最后一条。

**参数表**（全部可选）：

| 参数 | 默认 | 说明 |
|------|------|------|
| `--dns-port` | 15353 | 平台 DNS 监听端口（代理转发到这里） |
| `--web-port` | 8080 | Web 管理端口 |
| `--upstream-dns` | 223.5.5.5 | 公网递归 DNS（⚠️ 严禁指向本系统自身） |
| `--alert-ip` | 127.0.0.1 | 拦截引导页 IP（**生产必改**：指向内网告警页） |
| `--memory-max` | 24G | systemd 内存上限（16G 机器设 10G） |
| `--pip-mirror` | 清华源 | 无外网时换内网源 |
| `--install-dir` | /opt/dns-security-filter | 安装目录 |
| `--skip-tuning` | - | 跳过 sysctl/limits 调优 |

**装完立即做两件事**：
1. 记下屏幕打印的**管理员初始密码**（仅首次生成配置时显示一次）
2. 浏览器登录 `http://机B_IP:8080` → 立即修改密码

### 3.3 若中途失败的恢复

脚本幂等，直接重跑即可。唯一注意点：**venv 半成品残留**——若上次失败在 venv 创建环节（报 `ensurepip ... non-zero exit status 1`），修复脚本会自动清理；用旧版脚本时手动清一下再重跑：

```bash
rm -rf /opt/dns-security-filter/platform/venv
# 补齐缺失包（昨天的报错根因）后重跑：
dnf install -y python3.12-pip python3.12-setuptools
sudo bash ./deploy/install-platform.sh --upstream-dns 223.5.5.5 --alert-ip 10.0.0.99
```

## 四、机 A（代理）安装

```bash
# 仓库目录同样上传到机 A（或从机 B 的 /root/dns-security-filter scp 过去）
cd /root/dns-security-filter
sudo bash ./deploy/install-proxy.sh --upstream <机B内网IP> --upstream-port 15353
```

脚本做 8 件事（幂等）：环境检测（53 端口占用提示）→ 用户与目录 → 二进制安装 + **setcap 授权绑 53** → 生成 config.yaml → systemd 服务启动 → 内核参数 → 句柄上限 → 自检。

**参数表**：

| 参数 | 默认 | 说明 |
|------|------|------|
| `--upstream` | 127.0.0.1 | ★ 机 B 内网 IP |
| `--upstream-port` | 15353 | 与机 B 的 `--dns-port` 一致 |
| `--listen-port` | 53 | 本机监听端口（域控转发器指向它） |
| `--forward-timeout` | 8 | 转发超时秒（生产 ≥8，勿降） |
| `--binary` | bin/dns-proxy | 预编译二进制路径 |
| `--install-dir` | /opt/dns-security-filter | 安装目录 |

> 代理是静态 Go 二进制（CGO_ENABLED=0 编译，无任何动态库依赖），机 A 无需装 Python 和任何系统包。

## 五、上联网络放行（系统层无 firewalld，这步是安全底线）

找网络组在上联防火墙/核心交换机实施以下 ACL（**端口与来源要求是安全底线，不可省略**）：

| 机器 | 端口 | 只允许来源 |
|------|------|-----------|
| 机 A | 53/UDP+TCP | 各域控（DC）网段 |
| 机 B | 15353/UDP+TCP | 仅机 A 内网 IP |
| 机 B | 8080/TCP | 仅运维网段/堡垒机 |

机 B 还需**出站**白名单（大名单下载/在线情报/公网递归）：

| 类别 | 地址 | 端口 |
|------|------|------|
| 公网递归 DNS | 223.5.5.5 主 / 119.29.29.29 备 | UDP/TCP 53 |
| 离线大名单 | raw.githubusercontent.com、cdn.jsdelivr.net（镜像降级）、urlhaus.abuse.ch、threatfox.abuse.ch | 443/TCP（C2IntelFeeds 走 raw/jsDelivr，无新增域名） |
| DNSBL 在线源 | **无需单独放通**（走上方公网递归 53 出站；不是访问网站，是通过递归查 A 记录） | — |
| HTTP 在线源（可选，手工创建源并启用才开） | urlhaus-api.abuse.ch、threatfox-api.abuse.ch、api.threatbook.cn、api.xforce.ibmcloud.com、otx.alienvault.com、api.greynoise.io、checkurl.phishtank.com | 443/TCP |

**代理出站（可选，简化防火墙策略）**：机 B 无法直连上述公网地址时，可部署一台可达的 HTTP 正向代理，Web → 系统配置 → 情报出站代理填 `http://代理IP:端口` 保存（支持连通性预检按钮）。之后在线情报源查询与离线大名单下载全部经代理转发（DNSBL 走 DNS 协议不经代理，公网递归 53 出站仍需单独放通）；出站白名单收敛为"代理服务器 IP:端口 + 公网递归 53"两条。代理地址修改即时生效（Web 进程立即、DNS 进程约 1 分钟内经轮询同步），清空即恢复直连。

## 六、上线验证清单（全部通过才切域控）

在机 A / 机 B / 任意内网机分别执行：

| # | 验证项 | 命令 | 预期 |
|---|--------|------|------|
| 1 | 服务三件套 | `systemctl status proxy platform-dns platform-web`（两机分别查各自的） | 全部 running + enabled |
| 2 | 平台健康 | `curl -s http://127.0.0.1:8080/api/health`（机 B） | `{"code":0,...,"status":"up"}` |
| 3 | 链路连通 | 机 A：`dig +short @机B_IP -p 15353 www.baidu.com` | 返回真实 IP |
| 4 | 全链路 | 内网机：`dig +short @机A_IP www.baidu.com` | 返回真实 IP |
| 5 | 二查延迟 | 同一域名连 dig 两次，看第二次 | <50ms（缓存命中） |
| 6 | 黑名单拦截 | Web → 人工情报源 → 黑名单加 `test-block.example.com` → 内网机 dig | 返回 alert_ip（10.0.0.99），而非真实 IP |
| 7 | 拦截日志与终端 IP | Web → 过滤日志 | 有记录，client_ip 为发起 dig 的机器 IP |
| 8 | 误拦应急 | Web 把测试域名加白名单 → 再 dig | 秒级恢复真实 IP |
| 9 | 容灾演练 | 机 B：`systemctl stop platform-dns` → 内网机 dig | 约 8s 后 SERVFAIL（快速失败不挂起）；改 DC 转发器回公网立即恢复；恢复后 `systemctl start platform-dns` |
| 10 | 压测基准 | 机 B：`python3 tools/loadtest.py --target 127.0.0.1:15353 --qps 1000 --duration 60`（需在仓库目录） | P95 <100ms、无丢包 |
| 11 | 备份验证 | `systemctl list-timers dnsfilter-backup.timer`；`sudo systemctl start dnsfilter-backup.service && ls /var/backups/dnsfilter/` | timer active；目录出现 .gz 备份文件 |

> 10 万终端规模另需按容量模型做阶梯压测（1000→10000→30000 QPS）与风暴演练，命令与验收口径见仓库 docs/《生产环境部署方案（Linux 双机）》第 4.1 节；当前灰度阶段先过本表 11 项。

## 七、导入离线大名单（切域控前完成）

Web → 威胁情报 → 离线情报源：

1. 首选 **hagezi_mini**（17 万条，内存约 1/12）——灰度起步推荐
2. 点导入，等待完成（首导约 1~2 分钟，前端有进度条）
3. 导入后用第六节第 6 项方法验证：找一个名单里的域名 dig 应返回 alert_ip
4. 机器内存 ≥32G 后可升级 hagezi_ti（210 万条）或加开 oisd（每日低误报交叉验证）

> 自动更新默认关闭（`threatlist_auto_update: false`）。灰度稳定后可在 Web 开启并设周期（如 24h），urlhaus 源固定 30 分钟哨兵不受用户周期影响。

## 八、切换域控（灰度）

1. **选用户最少的一台 DC 先切**：DNS 管理器 → 服务器属性 → 转发器
2. **先记录/截图原转发器配置**（容灾回退备份）
3. 删除原公网转发器，添加 **机 A 的 IP**；转发器超时设 **8~10s**
4. 观察 **3~7 天**：拦截日志、误报、终端反馈、平台资源曲线（Web 总览页）
5. 无异常后逐台追加 DC，每台间隔 ≥1 天

**EDNS0 说明**：Windows Server 2012+ DC 默认附加 Client Subnet，平台据此记录真实终端 IP；若组策略曾设 `DisableEDNSProbes=1` 需移除。哑终端可能不带 ECS（client_ip 为空）——不影响过滤，只影响日志定位，属预期。

## 九、容灾与回退（背下来）

| 故障 | 现象 | 处置 |
|------|------|------|
| 机 B 平台挂 | 全网 SERVFAIL | **任一 DC 转发器改回公网 DNS，该 DC 覆盖终端立即恢复**（多 DC 可分批放）；修复后再切回 |
| 机 A 代理挂 | DC 转发超时 | DC 转发器临时直指机B:15353 或回公网 |
| 误拦截业务域名 | 业务异常 | Web 加白名单秒级生效；或 Web 系统配置把 detection_enabled 切 false（全放行止血） |
| 公网 DNS 出站断 | 解析失败 | 检查上联防火墙出站；确认 223.5.5.5 可达 |

> 原则（安全优先）：故障不自动放行，人工决策切换。紧急场景**优先保业务**（回退转发器），事后补审计。

## 十、常见问题速查

| 现象 | 原因 | 处置 |
|------|------|------|
| venv 创建报 `ensurepip ... exit status 1` | 只装了 python3.12 没装 pip 包（RHEL 拆包） | `dnf install -y python3.12-pip python3.12-setuptools`；`rm -rf /opt/dns-security-filter/platform/venv` 后重跑脚本 |
| venv 三条兜底全失败，日志含 `pyexpat ... undefined symbol` | **8.5 老底子 + el8_10 新 python3.12 混搭**：pyexpat.so 需要新版 expat 符号，系统 expat 还是 2.2.5 | `dnf update -y expat`（升到 2.5.0+）后重跑；根治建议 `dnf update -y` 整体升到 8.10 基线 |
| `dnf install python3.12` 提示无包 | 系统未升到 8.10 | `dnf update` 升系统；或改装 python3.11 + pip + setuptools 效果等同 |
| dig 机 A 53 超时 | 上联 ACL 没放行来源段 | 核对第五节端口表；测试机 IP 是否在 DC 网段内 |
| 安装脚本健康接口无应答 | 服务仍在预热（大名单导入中） | 等 1~2 分钟；`journalctl -u platform-web -n 20` 看日志 |
| 改了 yaml 不生效 | dns/web/database 三段须重启 | `systemctl restart platform-dns platform-web`（或 proxy） |
| Web 登录 401 循环 | 服务器时间漂移导致 JWT 校验失败 | 检查 chronyd；`timedatectl status` 看同步状态 |
| 备份目录为空 | timer 未触发过（02:30 才跑） | `sudo systemctl start dnsfilter-backup.service` 手工触发验证 |
| 旧版脚本装的机器服务起不来（permission denied） | 旧版以 dnsfilter 专用用户运行，目录属主/53 端口授权时序问题 | 升级到当前脚本重跑（服务改为 root 运行）；或临时 `chown -R dnsfilter:dnsfilter /opt/dns-security-filter` + `setcap cap_net_bind_service=+ep .../bin/dns-proxy` |
| 离线导入/在线源报 `[Errno 99] Cannot assign requested address` | 服务器 IPv6 半配置（有接口无路由），httpx 试 AAAA 掩盖 IPv4 真实状态 | 已修复（出站强制 IPv4）；若仍失败看 journalctl 新日志，那是 IPv4 的真实错误（如 443 出站不通 → 配代理或放通） |
| 离线导入/在线源全部超时但 curl 手测通 | 机 B 出站被 ACL 限制，直连情报域名不通 | Web → 系统配置 → 情报出站代理填 `http://代理IP:端口`（先点"测试代理"预检）；DNSBL 不受影响仍走公网递归 |

> **切换运行用户（可选）**：当前所有服务默认以 root 运行。若组织安全基线强制要求非特权用户：`useradd -r -s /usr/sbin/nologin dnsfilter` → 四个 service 文件加回 `User=dnsfilter` / `Group=dnsfilter` → 机 A 执行 `setcap cap_net_bind_service=+ep /opt/dns-security-filter/bin/dns-proxy` → `chown -R dnsfilter:dnsfilter /opt/dns-security-filter /var/backups/dnsfilter` → `systemctl daemon-reload && systemctl restart proxy platform-dns platform-web`。注意每次重跑安装脚本前需先手动 chown（脚本不再代管属主）。

## 十一、配置速查（装完后改配置从这里查）

| 场景 | 操作 |
|------|------|
| 机 A 代理参数 | 编辑 `/opt/dns-security-filter/proxy/config.yaml` → `systemctl restart proxy` |
| 机 B dns/web/database 三段 | 编辑 `/opt/dns-security-filter/platform/platform.yaml` → `systemctl restart platform-dns platform-web` |
| 检测/日志/缓存类参数 | Web → 系统配置（在线热生效，优先级高于 yaml，存 SQLite） |
| 情报出站代理 | Web → 系统配置 → 情报出站代理（填 `http://IP:端口`，留空直连；含测试按钮；在线源+大名单下载走代理，DNSBL 不走） |
| Web 改名单/配置后 DNS 进程感知 | 自动（cross_sync 60s 轮询），无需重启 |
| 服务日志 | `journalctl -u platform-dns -f`（或 proxy / platform-web） |
| 数据库 | `/opt/dns-security-filter/platform/data/platform.db`，每日 02:30 自动热备到 `/var/backups/dnsfilter/`（保留 14 份） |

---

## 附：本文档与仓库其他文档的关系

- **本文档**：AlmaLinux 8 环境的实操主线（装好就走，覆盖 95% 场景）
- **《生产环境部署方案（Linux 双机）》**：完整技术方案——容量模型、压测方法、检测链路细节、风险边界（容量验证阶段需要）
- 两者不一致时以本文档为准（本文档按实际环境基线编写）
