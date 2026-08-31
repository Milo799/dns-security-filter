# DNS 安全过滤中间件 - Harness 工程

基于《Windows DNS 安全过滤中间件 开发PRD V2.0》与《需求说明书（完整版 V2.1）》开发的项目工程（monorepo）。
**16 轮迭代需求已全部实现**，pytest 205 项全绿，最小可运行闭环 → 全功能交付。

## 架构（三层 + 离线大名单）

```
Windows DNS（多台，仅配转发器，零安装）
   │ 外网域名请求（含 EDNS0 Client Subnet 透传客户端 IP）
   ▼
DNS 代理中间件（Go + miekg/dns，独立部署，纯转发，无检测逻辑）
   │ 标准 DNS 协议（UDP/TCP 53）
   ▼
DNS 安全过滤平台（Python，监听 53）
   ├─ 检测链路（A / AAAA / PTR 同等过滤）
   │    ① 手工白名单 → ② 手工黑名单 → ③ 离线大名单（内存 O(1)）
   │    → ④ 在线威胁情报（16 适配器并行 + 融合裁决） → ⑤ IP 后置过滤
   ├─ 离线大名单自动更新（按源周期 + jsDelivr 镜像降级）
   └─ Web 管理（FastAPI :8080，单文件 SPA）
```

平台故障时：在 Windows DNS 上人工修改转发器地址，改回公网 DNS 绕过（不做自动容错）。

## 目录结构

| 目录 | 内容 | 状态 |
|------|------|------|
| `proxy/` | Go 代理中间件（main/config/forward + 配置模板） | ✅ 已实现，待 Go 环境编译验证 |
| `platform/` | 平台：dns_server（ECS/PTR）、detectors 五层检测、adapters（16 适配器）、threat_list（离线大名单）、app(FastAPI+SQLite)、seed | ✅ 已实现 |
| `web/` | 管理前端（单文件 SPA，SAP Fiori 风格：拆页黑白名单/情报源表格/测试中心/调度可视化） | ✅ 已实现 |
| `deploy/` | systemd unit ×3 + **一键安装脚本 install-proxy.sh / install-platform.sh**；**`deploy/docker/`** 镜像编排 + 网络白名单 | ✅ 已实现 |
| `scripts/` | dev.sh（一键启动）、verify.sh（dig 验证）、fake_upstream.py | ✅ 已实现 |
| `tests/` | pytest 205 项（融合/拦截/ECS/PTR/大名单/情报源/调度/性能） | ✅ 全绿 |
| `docs/` | 需求说明书 V2.1（需求基线）、开发 PRD V2.0（实现基线） | ✅ |

## 快速开始

### 方式一：Docker（推荐，Linux）

```bash
# 一键构建并启动（平台 DNS :53 + Web :8080，代理 :53）
docker compose -f deploy/docker/docker-compose.yml up -d --build

# 网络出站白名单清单见 deploy/docker/README.md（四类：构建期/大名单/在线情报/上游 DNS）
```

### 方式二：一键脚本（Linux 生产，systemd）

```bash
# 机 B（检测平台）：自动 venv+依赖、生成随机密钥与全注释配置、装 systemd 并自检
sudo ./deploy/install-platform.sh --upstream-dns 223.5.5.5 --alert-ip <告警页IP>

# 机 A（代理）：需先交叉编译 bin/dns-proxy（见 5.0 节）
sudo ./deploy/install-proxy.sh --upstream <机B内网IP>

# 参数与脚本行为详见 docs/生产环境部署方案（Linux 双机）.md 第五节
```

### 方式三：裸机 / 开发调试（Linux）

```bash
# 1. 平台依赖
cd platform && pip install -r requirements.txt

# 2. 初始化数据库（建表 + 默认管理员 admin/admin123 + 内置情报源 seed）
python -m seed

# 3. 启动平台（DNS :53 + Web :8080）—— 生产用一键脚本（见上），开发可改端口调试
python dns_server.py &                                              # DNS 服务
python -m uvicorn app.main:app --host 0.0.0.0 --port 8080 &         # Web

# 4. 构建并启动代理（Go 1.21+；53 端口需 root 或 CAP_NET_BIND_SERVICE）
cd proxy && cp proxy.example.yaml config.yaml && go build -o ../bin/dns-proxy .
./bin/dns-proxy -config config.yaml

# 5. 验证链路
dig @<代理IP> example.com A

# 6. 配置 Windows DNS 转发器指向 代理IP:53（外网域名），并禁用根提示
```

## 验收基准

| 命令 | 含义 |
|------|------|
| `make test` | 全部 205 项测试通过 |
| `make verify` | dig 经代理查询成功返回 IP（链路通） |
| `make docker-up` ▲ | Docker compose 一键构建启动 |
| 拦截验证 | 黑名单/离线大名单/威胁情报配置后，`dig` 恶意域名返回告警 IP（AAAA 为空应答），filter_log 可查 |
| 调度验证 ▲ | 离线大名单页展示各源实际周期、下次更新时间与倒计时；自动更新按 min(源周期, 全局配置) 到期触发 |

## 关键约束（开发必须遵守）

- 代理为**纯转发器**：不修改报文、不剥离 EDNS0（含 OPT RR），不加检测逻辑
- 平台**不缓存** DNS 记录；**A / AAAA / PTR 同等过滤**
- 拦截应答：A 返回告警 IP；AAAA 返回空应答（NOERROR）；不返回 NXDOMAIN
- 威胁情报**三态语义**：命中→拦截；明确未命中→放行；网络失败/超时/缺 Key→无结论（不参与融合统计）；**全部源无结论默认拦截**（fail-safe）
- 适配器按**能力声明**（domain/ip）分配查询；异常/超时返回 None 不抛异常；维护 `last_error` 供诊断
- 离线大名单：整源替换导入、内存缓存匹配；写路径（导入/启停/清空）必须调 `invalidate()` 联动失效内存缓存与统计缓存
- 自动更新各源实际周期 = min(源内置 update_interval_s, 用户全局配置间隔)；调度可视化到期判断口径与此一致
- 日志必录被拦截/剔除请求（filter_log 全字段）；放行日志可选（默认关）
- 部署：Linux systemd / Docker 为准；Windows 部署仅备用

详见 `AI_AGENTS.md`（AI 开发指引）与 `docs/` 下 PRD V2.0 / 需求说明书 V2.1。
