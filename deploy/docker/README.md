# Docker 部署说明（Linux）

> 与 `deploy/install.sh`（systemd 原生部署）二选一；**Docker 方式优先推荐**——一条命令拉起
> 平台（DNS 53 + Web 8080）与代理（DNS 53/5353）两个服务，配置通过 volume 挂载，镜像可移植。

## 一、目录结构

```
deploy/docker/
├── Dockerfile.platform      # 平台镜像（Python：dns_server + uvicorn 双进程）
├── Dockerfile.proxy         # 代理镜像（Go 多阶段构建 → alpine）
├── docker-compose.yml       # 编排：platform + proxy
└── platform-entrypoint.sh   # 平台容器入口（后台 DNS 服务 + 前台 Web）
```

## 二、快速启动

```bash
# 1. 进入仓库根目录，按环境修改配置
vim platform/platform.yaml      # jwt_secret、admin_initial_password、upstream_dns、alert_ip 必改
vim proxy/config.yaml           # 复制自 proxy.example.yaml；upstream_addr 填 platform（compose 服务名）

# 2. 构建并启动
docker compose -f deploy/docker/docker-compose.yml up -d --build

# 3. 验证
docker compose -f deploy/docker/docker-compose.yml ps
curl http://127.0.0.1:8080/api/health          # 期望 {"code":0,"message":"ok","data":{"status":"up"}}
docker exec dnsfilter-platform python -c "import socket;print(socket.getaddrinfo('example.com',53))"  # DNS 服务存活
```

## 三、配置指引

| 文件 | 必改项 | 说明 |
|------|--------|------|
| `platform/platform.yaml` | `jwt_secret`、`admin_initial_password` | 生产必须修改，否则默认口令可登录 |
| 同上 | `database` | **容器内填 `/app/data/platform.db`**（compose 已把 `platform/data` 挂到 `/app/data`） |
| 同上 | `upstream_dns` | 平台递归解析用的公网 DNS（默认 8.8.8.8，可按需改 114.114.114.114） |
| 同上 | `alert_ip` | 拦截应答的告警 IP（A 记录），建议填告警页面服务器地址 |
| 同上 | `web.listen_port` | Web 端口，需与 compose 中 `WEB_PORT`/端口映射一致（默认 8080） |
| `proxy/config.yaml` | `upstream_addr` | 指向平台：compose 内填 `platform`；代理独立机器部署填平台 IP |
| 同上 | `listen_port` | 默认 53；与平台同机时改 5353（compose 已按此映射） |

数据持久化：`platform/data/` 目录挂载为 volume，SQLite 库（含黑白名单、情报源配置、日志）存于容器外。
前端静态页（`web/`）直接打进镜像，改前端需重建镜像；也可在 compose 中补挂 `../../web:/app/web:ro` 热替换。

## 四、故障回退（与 systemd 部署一致）

平台/代理任一故障 → 在 Windows DNS 上把转发器地址改回原公网 DNS，外网解析立即绕过过滤；
恢复后改回指向代理。备份原转发器配置便于快速切换。

## 五、需要开通的网络地址（防火墙/安全组出站白名单）

部署机 **入站** 需放行：`53/UDP+TCP`（DNS）、`8080/TCP`（Web 管理，建议仅内网）、
代理独立部署时另放行代理的 `53/UDP+TCP`。

部署机 **出站** 按功能模块分四类（未启用对应功能源时可不开通对应项）：

### 1. 构建期（仅构建镜像时需要，运行期可关）
| 地址 | 用途 |
|------|------|
| `docker.io` / `registry-1.docker.io` / `auth.docker.io`（或公司内镜像仓库） | 拉取 python/golang/alpine 基础镜像 |
| `pypi.org`、`files.pythonhosted.org`（或 `pypi.tuna.tsinghua.edu.cn`） | 安装 Python 依赖 |
| `proxy.golang.org`（或 `goproxy.cn`） | 下载 Go module（构建代理镜像） |

### 2. 离线大名单下载（`/api/threatlist/import` 与自动更新）
| 地址 | 来源 | 端口/协议 |
|------|------|-----------|
| `raw.githubusercontent.com` | hagezi（ti/ult/mini）、StevenBlack、OISD 主地址 | 443/TCP |
| `cdn.jsdelivr.net` | 上述仓库的镜像降级地址 | 443/TCP |
| `urlhaus.abuse.ch` | URLhaus 恶意域名哨兵名单 | 443/TCP |
| `threatfox.abuse.ch` | ThreatFox C2 hostfile（每日，方案 C） | 443/TCP |

### 3. 在线威胁情报 API（启用对应适配器时才需；方案 C 后 HTTP 类不预置，手工创建源后才需要）
| 地址 | 适配器 | 端口/协议 |
|------|--------|-----------|
| `zen.spamhaus.org` / `dbl.spamhaus.org` | spamhaus_zen / spamhaus_dbl（DNSBL） | 53/UDP |
| `dnsbl.dronebl.org` | dronebl（DNSBL） | 53/UDP |
| `dnsbl.spfbl.net` | spfbl（DNSBL，默认停用可选启用） | 53/UDP |
| `urlhaus-api.abuse.ch` | URLhaus（在线查询版，需 Auth-Key） | 443/TCP |
| `threatfox-api.abuse.ch` | ThreatFox | 443/TCP |
| `api.threatbook.cn` | 微步威胁情报 | 443/TCP |
| `api.xforce.ibmcloud.com` | IBM X-Force | 443/TCP |
| `otx.alienvault.com` | AlienVault OTX | 443/TCP |
| `api.greynoise.io` | GreyNoise | 443/TCP |
| `checkurl.phishtank.com` | PhishTank | 443/TCP |
| `isc.sans.edu` | DShield | 443/TCP |
| `api.blocklist.de` | Blocklist.de | 443/TCP |

### 4. 上游公网递归 DNS（平台解析外网域名用）
| 地址 | 说明 |
|------|------|
| `8.8.8.8`、`8.8.4.4`（Google）或 `114.114.114.114`（国内） | `platform.yaml` 的 `upstream_dns`，UDP/TCP 53 出站 |

> 最小出站开通建议（仅用离线大名单 + 默认上游）：`raw.githubusercontent.com`、`cdn.jsdelivr.net`、
> `urlhaus.abuse.ch`、`threatfox.abuse.ch`、`8.8.8.8/8.8.4.4:53`。启用在线 API 源时按上表逐项添加。

## 六、常见问题

- **端口 53 被占用**：检查是否已有 systemd-resolved（`systemctl status systemd-resolved`）或本地 DNS；
  可改 `platform.yaml` 的 `dns.listen_port` 与 compose 映射为 5353 先用，转发器指对应端口。
- **平台容器内两个进程**：任一进程退出容器即退出并自动重启（`restart: unless-stopped`），
  日志 `docker logs dnsfilter-platform` 可见 DNS 与 Web 双进程输出。
- **改配置不生效**：配置以 volume 挂载（`platform.yaml` / `config.yaml`），改后需
  `docker compose -f deploy/docker/docker-compose.yml restart`。
- **国内拉镜像慢**：配置 Docker 镜像加速器，或把基础镜像改为内网仓库地址后重新 `--build`。
