# 生产部署指引（AlmaLinux 8）

> 本文是《生产环境部署方案（Linux 双机）》在 **AlmaLinux 8.5+** 上的 OS 专项补充：
> 只讲 AlmaLinux 8 特有的准备步骤与差异点，通用内容（拓扑、机器配置、验证清单、容灾回退）
> 一律以主方案文档为准。
>
> 为什么放弃 CentOS 7.8：EOL 后官方源已失效（yum 报 404/MirrorList 移除）；glibc 停在 2.17
> 导致 FastAPI 生态多个核心依赖（pydantic-core / cryptography / bcrypt 等 Rust/C 扩展包）
> 需要手工源码编译且要解决 OpenSSL 1.0 vs 1.1 头文件冲突；系统 Python 仅 3.6 距平台要求的
> 3.10 相差四个大版本。AlmaLinux 8 是 RHEL 8 的 1:1 兼容重建，glibc 2.28 覆盖全部依赖的
> 预编译轮子（manylinux_2_28），AppStream 仓库直接提供 python3.11，整体只多两三条命令。

---

## 一、两机共同的 OS 准备（AlmaLinux 8.5 出厂态 → 可部署态）

```bash
# ① 升级到 8.7+（关键：python3.11 包从 8.7 才进入 AppStream 仓库）
sudo dnf update -y && sudo reboot

# ② 装基础工具（脚本依赖 rsync/bash；自检与验证需要 curl/ss/dig/sqlite3）
sudo dnf install -y rsync curl sqlite iproute bind-utils

# ③ NTP 对时（主方案第二节强制要求；chrony 是 RHEL8 默认，确认启用即可）
timedatectl status | grep -E 'NTP|synchronized'
# 若未同步：sudo dnf install -y chrony && sudo systemctl enable --now chronyd

# ④ SELinux：保持默认 Enforcing 即可（服务不开端口例外不涉及策略；如遇个别环境报
#    AVC 拒绝且无暇排障，可临时 setenforce 0 验证，正式上线前恢复）
getenforce
```

**版本红线**：`dnf update` 后用 `cat /etc/almalinux-release` 确认 ≥ 8.7；
若内网环境无法升级到 8.7，`dnf install python39` 可以装 3.9 —— 但平台要求 ≥3.10，
此时只能源码编译或改用 docker 路线，不建议。

## 二、机 A（代理）——除准备外无额外步骤

代理是 **CGO_ENABLED=0 的纯静态 Go 二进制**（ELF、无动态库依赖），在 AlmaLinux 8 上
直接可用，无需任何系统包。执行主方案 5.0/5.2 节：

```bash
sudo ./deploy/install-proxy.sh --upstream <机B内网IP> --upstream-port 15353
```

## 三、机 B（检测平台）——唯一注意点是 Python 3.11

```bash
# ① 装 Python 3.11 + venv 模块（AppStream 提供，无需编译）
sudo dnf install -y python3.11 python3.11-pip

# ② 确认版本 ≥3.10（安装脚本也会自检，这里提前确认少走弯路）
python3.11 -V

# ③ 跑主方案 5.1 节的一键脚本（脚本会自动找到 python3.11 建 venv、装 9 个依赖）
sudo ./deploy/install-platform.sh --upstream-dns 223.5.5.5 --alert-ip <内网告警页IP>
```

**为什么顺畅**：RHEL 8 的 glibc 2.28 对应 manylinux_2_28 轮子标签，requirements.txt 全部
九个包（fastapi/uvicorn/pydantic 系/pyjwt/bcrypt/pyyaml/requests/cryptography/httpx）
均有官方预编译轮子，清华 pip 镜像直连下载，无需任何编译工具链。

## 四、防火墙（firewalld）

AlmaLinux 8 默认启用 firewalld。安装脚本不开端口（自检走本机回环不受影响），
上线前必须手工放行（与主方案 3.2 节的来源限制对应）：

```bash
# 机 A：53 仅对域控网段开放（示例 10.0.0.0/24 为 DC 所在段，按实际改）
sudo firewall-cmd --permanent --new-zone=dnsclients
sudo firewall-cmd --permanent --zone=dnsclients --add-source=10.0.0.0/24
sudo firewall-cmd --permanent --zone=dnsclients --add-port=53/udp
sudo firewall-cmd --permanent --zone=dnsclients --add-port=53/tcp
sudo firewall-cmd --reload

# 机 B：15353 仅对机 A 开放；8080 仅对运维网段（示例 10.0.255.0/24）
sudo firewall-cmd --permanent --new-zone=fromproxy
sudo firewall-cmd --permanent --zone=fromproxy --add-source=<机A内网IP>/32
sudo firewall-cmd --permanent --zone=fromproxy --add-port=15353/udp
sudo firewall-cmd --permanent --zone=fromproxy --add-port=15353/tcp
sudo firewall-cmd --permanent --new-zone=ops
sudo firewall-cmd --permanent --zone=ops --add-source=10.0.255.0/24
sudo firewall-cmd --permanent --zone=ops --add-port=8080/tcp
sudo firewall-cmd --reload
```

> 机 B 还需**出站**白名单（大名单下载/在线情报 API/公网递归 DNS），完整清单见主方案 3.1 节。
> 出站防火墙用 rich rule 或由网络团队在上联防火墙实施，本文不展开。

## 五、systemd 单元与 AlmaLinux 8 的适配说明

仓库自带 5 个 unit（proxy / platform-dns / platform-web / dnsfilter-backup.service/.timer）
全部使用标准指令（Type=simple、NoNewPrivileges、ProtectHome、PrivateTmp、LimitNOFILE、
MemoryMax、OnCalendar + Persistent timer），在 RHEL 8 的 systemd 239 上**全部原生支持**，
无需修改。两个安装脚本里的 sed 路径替换与 `hostname -I` 取 IP 写法在 AlmaLinux 8 上
同样开箱即用。

## 六、30 分钟全流程速查（贴墙版）

```
[0:00] 两机：dnf update → reboot → 装 rsync/curl/sqlite/chronyd 对时
[0:10] 开发机：交叉编译代理二进制（仓库已提供 bin/dns-proxy 时跳过）
       cd proxy && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ../bin/dns-proxy .
[0:12] 打包上传：仓库目录（含 bin/dns-proxy）scp 到两机 /root/ 或 /tmp/
[0:15] 机 B：dnf install python3.11 python3.11-pip
[0:18] 机 B：sudo ./deploy/install-platform.sh --upstream-dns 223.5.5.5 --alert-ip x.x.x.x
       （记下屏幕打印的管理员初始密码；登录 http://机B:8080 改密）
[0:25] 机 A：sudo ./deploy/install-proxy.sh --upstream <机B IP> --upstream-port 15353
[0:28] 两机防火墙放行（第四节命令）→ 主方案第七节 13 项验证清单逐项过
[后续] Web 导入离线大名单（hagezi_mini 起步）→ 灰度首台 DC（主方案第六/八节）
```

## 七、离线（无公网出站）部署变体

机房无公网时（大名单靠人工介质同步的场景）：

1. 有公网的跳板机：`python3.11 -m pip download -r requirements.txt -d wheels/ `
   （AlmaLinux 8 上下载即得 manylinux_2_28 轮子）+ 下载 hagezi 等名单 txt
2. 打包 `wheels/ + 仓库 + bin/dns-proxy` 一并 scp 到机 B
3. 机 B：`sudo dnf install python3.11` 后改用脚本参数
   `--pip-mirror file:///root/wheels` 或手工
   `venv/bin/pip install --no-index --find-links=/root/wheels -r requirements.txt`
4. dnf 无本地源时：`dnf install --disablerepo=* --enablerepo=baseos,appstream` 需内网
   镜像源（AlmaLinux 官方也提供离线 ISO 挂本地源，python3.11 在 AppStream ISO 内）

## 八、常见问题（AlmaLinux 8 专项）

| 现象 | 原因 | 处置 |
|------|------|------|
| `dnf install python3.11` 提示无包 | 8.5 仓库尚未收录（8.7 起有） | `dnf update` 升系统；或临时用 `dnf module enable python39` 不满足要求，须升级 |
| 脚本自检"未找到 Python >=3.10" | 只装了系统默认 python3（3.6） | `dnf install python3.11`；脚本按 python3.11 → python3.12 → python3.10 顺序探测 |
| firewalld rich rule 生效但 dig 不通 | zone source 网段写错（DC 网段 vs 本机网段） | `firewall-cmd --zone=dnsclients --list-all` 核对 add-source |
| SELinux AVC 拒绝（journalctl 有 denied） | 个别加固环境策略严格 | `ausearch -m avc -ts recent` 定位；通常平台写 /opt 与 /var/backups 在默认策略内 |
| chrony 未同步导致 JWT/审计时间漂移 | 虚机模板未配 NTP | `systemctl enable --now chronyd`；主方案第二节 NTP 为强制项 |
