# 生产部署指引（AlmaLinux 8）

> 本文是《生产环境部署方案（Linux 双机）》在 **AlmaLinux 8.5+** 上的 OS 专项补充：
> 只讲 AlmaLinux 8 特有的准备步骤与差异点，通用内容（拓扑、机器配置、验证清单、容灾回退）
> 一律以主方案文档为准。
>
> 为什么放弃 CentOS 7.8：EOL 后官方源已失效（yum 报 404/MirrorList 移除）；glibc 停在 2.17
> 导致 FastAPI 生态多个核心依赖（pydantic-core / cryptography / bcrypt 等 Rust/C 扩展包）
> 需要手工源码编译且要解决 OpenSSL 1.0 vs 1.1 头文件冲突；系统 Python 仅 3.6 距平台要求的
> 3.10 相差四个大版本。AlmaLinux 8 是 RHEL 8 的 1:1 兼容重建，glibc 2.28 覆盖全部依赖的
> 预编译轮子（manylinux_2_28），AppStream 仓库直接提供 python3.11/3.12，整体只多两三条命令。

---

## 一、两机共同的 OS 准备（AlmaLinux 8.5 出厂态 → 可部署态）

```bash
# ① 升级系统（关键：Python 包的收录版本随系统小版本走，见下方版本红线）
sudo dnf update -y && sudo reboot

# ② 装基础工具（脚本依赖 rsync/bash；自检与验证需要 curl/ss/dig/sqlite3）
sudo dnf install -y rsync curl sqlite iproute bind-utils

# ③ NTP 对时（主方案第二节强制要求；chrony 是 RHEL8 默认，确认启用即可）
timedatectl status | grep -E 'NTP|synchronized'
# 若未同步：sudo dnf install -y chrony && sudo systemctl enable --now chronyd

# ④ 关闭 SELinux（本环境策略，与 ① 的 reboot 合并一次完成）
sudo sed -i 's/^SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
sudo setenforce 0 2>/dev/null || true   # 立即生效（免重启临时态）
getenforce   # 预期输出 Disabled
```

**版本红线**：`dnf update` 后用 `cat /etc/almalinux-release` 确认版本与 Python 包的对应
关系（AppStream 收录时间不同）：

| Python 包 | 最低系统版本 |
|-----------|-------------|
| `python3.12` | **8.10** |
| `python3.11` | 8.7 |

dnf update 到 8.10 后 `dnf install python3.12` 直接可用；若因故停在 8.7~8.9，
改装 `python3.11` 同样满足平台 ≥3.10 要求（安装脚本自动探测，无需改参数）。

## 二、机 A（代理）——除准备外无额外步骤

代理是 **CGO_ENABLED=0 的纯静态 Go 二进制**（ELF、无动态库依赖），在 AlmaLinux 8 上
直接可用，无需任何系统包。执行主方案 5.0/5.2 节：

```bash
sudo ./deploy/install-proxy.sh --upstream <机B内网IP> --upstream-port 15353
```

## 三、机 B（检测平台）——注意 Python 的三个包都要装

```bash
# ① 装 Python（本环境采用 3.12；dnf update 到 8.10 后可用）
#    ⚠️ RHEL 系把 pip/setuptools 拆成独立包：只装 python3.12 会导致 venv 创建失败
#    （ensurepip 报错 exit status 1）——三个包一起装
sudo dnf install -y python3.12 python3.12-pip python3.12-setuptools
#    若系统停在 8.7~8.9 装不到 3.12，改装 python3.11 + python3.11-pip + python3.11-setuptools 效果等同

# ② 确认版本与 pip 模块都在（安装脚本也会自检，这里提前确认少走弯路）
python3.12 -V && python3.12 -m pip --version

# ③ 跑主方案 5.1 节的一键脚本（脚本自动找到 python3.12 建 venv、装 9 个依赖）
sudo ./deploy/install-platform.sh --upstream-dns 223.5.5.5 --alert-ip <内网告警页IP>
```

> **踩坑记录（2026-08-31 实测）**：只装 `python3.12` 不装 `python3.12-pip` 时，
> 安装脚本在 venv 创建的 ensurepip 环节报
> `Error: Command '...venv/bin/python3.12 -m ensurepip ...' returned non-zero exit status 1`。
> 补装 pip 包后直接重跑安装脚本即可（脚本幂等，且失败时会自动清理半成品 venv）。
> 若 venv 残留导致异常，`rm -rf /opt/dns-security-filter/platform/venv` 后重跑。

**为什么顺畅**：RHEL 8 的 glibc 2.28 对应 manylinux_2_28 轮子标签，requirements.txt 全部
九个包（fastapi/uvicorn/pydantic 系/pyjwt/bcrypt/pyyaml/requests/cryptography/httpx）
均有官方预编译轮子，清华 pip 镜像直连下载，无需任何编译工具链。

## 四、防火墙与 SELinux（本环境策略：系统层全关，边界防护上移）

**运维策略声明**：本环境 firewalld 与 SELinux **均关闭**，访问控制由上联防火墙/网络设备
统一实施（见下方补偿要求）。系统层不再单独维护 zone/rule，减少一层排障变量。

```bash
# 两机执行（关机重启后保持关闭状态）
sudo systemctl disable --now firewalld
# SELinux 已在第一节 ④ 关闭（配置文件 disabled + setenforce 0）
```

**关闭系统防火墙后的边界补偿（必须落实，对应主方案 3.2 节来源限制）**：

| 端口 | 服务 | 只允许的来源 | 实施位置 |
|------|------|-------------|---------|
| 机 A `53/UDP+TCP` | dns-proxy | 各域控（DC）网段 | 上联防火墙/核心交换机 ACL |
| 机 B `15353/UDP+TCP` | platform-dns | 仅机 A 内网 IP | 上联防火墙/交换机 ACL 或 VLAN 隔离 |
| 机 B `8080/TCP` | platform-web | 仅运维网段/堡垒机 | 上联防火墙/交换机 ACL |

> 机 B 还需**出站**白名单（大名单下载/在线情报 API/公网递归 DNS），完整清单见主方案 3.1 节，
> 同样在上联防火墙实施。
>
> **若上联防护暂不具备**，临时可先依赖交换机端口隔离或管理 VLAN（8080 不暴露到办公网），
> 但 53/15353 的来源限制属于安全底线（防止非 DC 设备直打过滤链路），上线前必须到位。

systemd 单元内的加固指令（NoNewPrivileges / ProtectHome / PrivateTmp 等）不受本策略影响，
仍然生效——它们是进程级约束，与系统防火墙/SELinux 无关。

## 五、systemd 单元与 AlmaLinux 8 的适配说明

仓库自带 5 个 unit（proxy / platform-dns / platform-web / dnsfilter-backup.service/.timer）
全部使用标准指令（Type=simple、NoNewPrivileges、ProtectHome、PrivateTmp、LimitNOFILE、
MemoryMax、OnCalendar + Persistent timer），在 RHEL 8 的 systemd 239 上**全部原生支持**，
无需修改。两个安装脚本里的 sed 路径替换与 `hostname -I` 取 IP 写法在 AlmaLinux 8 上
同样开箱即用。

## 六、30 分钟全流程速查（贴墙版）

```
[0:00] 两机：dnf update → 关 SELinux（改 config + setenforce 0）→ reboot
       装 rsync/curl/sqlite；关 firewalld；确认 chronyd 对时
[0:10] 开发机：交叉编译代理二进制（仓库已提供 bin/dns-proxy 时跳过）
       cd proxy && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ../bin/dns-proxy .
[0:12] 打包上传：仓库目录（含 bin/dns-proxy）scp 到两机 /root/ 或 /tmp/
[0:15] 机 B：dnf install python3.12 python3.12-pip python3.12-setuptools
[0:18] 机 B：sudo ./deploy/install-platform.sh --upstream-dns 223.5.5.5 --alert-ip x.x.x.x
       （记下屏幕打印的管理员初始密码；登录 http://机B:8080 改密）
[0:25] 机 A：sudo ./deploy/install-proxy.sh --upstream <机B IP> --upstream-port 15353
[0:28] 上联防火墙按第四节端口表放行（系统层已无 firewalld）
       → 主方案第七节 15 项验证清单逐项过
[后续] Web 导入离线大名单（hagezi_mini 起步）→ 灰度首台 DC（主方案第六/八节）
```

## 七、离线（无公网出站）部署变体

机房无公网时（大名单靠人工介质同步的场景）：

1. 有公网的跳板机：`python3.12 -m pip download -r requirements.txt -d wheels/ `
   （AlmaLinux 8 上下载即得 manylinux_2_28 轮子；跳板机同样需 python3.12-pip）+ 下载 hagezi 等名单 txt
2. 打包 `wheels/ + 仓库 + bin/dns-proxy` 一并 scp 到机 B
3. 机 B：`sudo dnf install python3.12 python3.12-pip python3.12-setuptools` 后改用脚本参数
   `--pip-mirror file:///root/wheels` 或手工
   `venv/bin/pip install --no-index --find-links=/root/wheels -r requirements.txt`
4. dnf 无本地源时：`dnf install --disablerepo=* --enablerepo=baseos,appstream` 需内网
   镜像源（AlmaLinux 官方也提供离线 ISO 挂本地源，python3.12 在 AppStream ISO 内）

## 八、常见问题（AlmaLinux 8 专项）

| 现象 | 原因 | 处置 |
|------|------|------|
| `dnf install python3.12` 提示无包 | 系统未升到 8.10（python3.12 从 8.10 起收录） | `dnf update` 升系统；或改装 `python3.11`（8.7 起有，同样满足 ≥3.10） |
| 脚本自检"未找到 Python >=3.10" | 只装了系统默认 python3（3.6） | `dnf install python3.12`；脚本探测顺序 python3 → python3.12 → python3.11 → python3.10 |
| venv 创建报 `ensurepip ... non-zero exit status 1` | **只装了 python3.12 没装 pip 包**（RHEL 系单独拆包，最常见坑） | `dnf install -y python3.12-pip python3.12-setuptools` 后重跑安装脚本（幂等）；venv 残留异常时 `rm -rf /opt/dns-security-filter/platform/venv` 再重跑 |
| 内网机器 dig 机 A 53 不通 | 系统层 firewalld 已关，但上联设备有 ACL | 找网络组核对上联防火墙/交换机 ACL 是否放行来源段（第四节端口表） |
| `getenforce` 输出 Enforcing | 只 setenforce 0 没改配置文件（重启会复原） | `sed -i 's/^SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config` 后重启 |
| chrony 未同步导致 JWT/审计时间漂移 | 虚机模板未配 NTP | `systemctl enable --now chronyd`；主方案第二节 NTP 为强制项 |
