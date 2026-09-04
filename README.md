# DNS 安全过滤中间件 - Harness 工程

基于《Windows DNS 安全过滤中间件 开发PRD V2.1》与《需求说明书（完整版 V2.2）》开发的项目工程（monorepo）。
**22 轮迭代需求已全部实现**，pytest 278 项全绿，最小可运行闭环 → 全功能交付 → 10 万终端性能优化。

## 架构（三层 + 离线大名单 + 检测缓存）

```
Windows DNS（多台，仅配转发器，零安装）
   │ 外网域名请求（含 EDNS0 Client Subnet 透传客户端 IP）
   ▼
DNS 代理中间件（Go + miekg/dns，独立部署，纯转发，无检测逻辑）
   │ 标准 DNS 协议（UDP/TCP 53）
   ▼
DNS 安全过滤平台（Python，监听 53）
   ├─ 检测链路（A / AAAA / PTR 同等过滤，域名/IP 双结论缓存）
   │    ① 手工白名单 → ② 手工黑名单 → ③ 离线大名单（内存 O(1)）
   │    → ④ 在线威胁情报（16 适配器并行 + 融合裁决 + 熔断；出厂默认仅 DNSBL 三源）
   │    → ⑤ IP 后置过滤（并行 + 单次上游往返，全正常返回上游原始应答）
   ├─ 离线大名单自动更新（按源周期 + jsDelivr 镜像降级）
   ├─ 高并发支撑（日志异步削峰 + 放行采样 + 限流熔断；1000QPS P95=1.86ms）
   ├─ 跨进程同步（cross_sync 60s 轮询，Web 改配置/名单 DNS 进程自动生效）
   └─ Web 管理（FastAPI :8080，多文件 SPA，SOC 深浅双主题大屏）
```

平台故障时：在 Windows DNS 上人工修改转发器地址，改回公网 DNS 绕过（不做自动容错）。

## 目录结构

| 目录 | 内容 | 状态 |
|------|------|------|
| `proxy/` | Go 代理中间件（main/config/forward/ecs + 配置模板；转发前注入客户端 ECS，已有 ECS 透传） | ✅ 已实现并编译验证（端到端含 ECS 注入链路） |
| `platform/` | 平台：dns_server（ECS/PTR）、detectors 五层检测、adapters（16 适配器）、threat_list（离线大名单）、domain_cache/ip_cache（结论缓存）、circuit_breaker（熔断：源级+路径级+上游熔断 fast-fail）、log_writer（日志削峰）、log_retention（保留期清理）、cross_sync（跨进程同步）、queue_stats（线程池队列观测）、query_stats（今日请求全量统计）、app(FastAPI+SQLite+crypto)、seed | ✅ 已实现 |
| `web/` | 管理前端（多文件 SPA：css/{theme,base,pages} + js/{app,charts,boot} + js/pages/×9；SOC 深浅双主题、安全态势大屏、人工情报源双 Tab） | ✅ 已实现 |
| `deploy/` | systemd unit ×3 + backup timer + **一键安装脚本 install-proxy.sh / install-platform.sh**；**`deploy/docker/`** 镜像编排 + 网络白名单 | ✅ 已实现 |
| `tools/` | loadtest.py（DNS 压测：QPS/延迟分位）、backup_db.sh（DB 每日热备+轮转） | ✅ 已实现 |
| `scripts/` | dev.sh（一键启动）、verify.sh（dig 验证）、fake_upstream.py | ✅ 已实现 |
| `tests/` | pytest 349 项（融合/拦截/ECS/PTR/大名单/情报源/调度/性能/缓存/并行/跨进程同步/线程池复用/上游熔断/队列观测/查询统计） | ✅ 全绿 |
| `docs/` | 需求说明书 V2.2（需求基线）、开发 PRD V2.1（实现基线）、生产部署方案（Linux 双机） | ✅ |

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
| `make test` | 全部 278 项测试通过 |
| `make verify` | dig 经代理查询成功返回 IP（链路通） |
| `make docker-up` ▲ | Docker compose 一键构建启动 |
| 拦截验证 | 黑名单/离线大名单/威胁情报配置后，`dig` 恶意域名返回告警 IP（AAAA 为空应答），filter_log 可查 |
| 调度验证 ▲ | 离线大名单页展示各源实际周期、下次更新时间与倒计时；自动更新按 min(源周期, 全局配置) 到期触发 |
| 压测验证 | `python tools/loadtest.py <平台IP> --qps 1000`（1000QPS 全收 P95<5ms；观测 `GET /api/log-writer/stats` dropped=0） |

## 关键约束（开发必须遵守）

- 代理为**纯转发器**：不修改报文、不剥离 EDNS0（含 OPT RR），不加检测逻辑
- 平台不缓存 DNS 记录（检测结论缓存 domain_cache/ip_cache 只缓存情报结论，不缓存 DNS 应答）；**A / AAAA / PTR 同等过滤**
- 拦截应答：A 返回告警 IP；AAAA 返回空应答（NOERROR）；不返回 NXDOMAIN
- 威胁情报**三态语义**：命中→拦截；明确未命中→放行；网络失败/超时/缺 Key→无结论（不参与融合统计）；**全部源无结论默认拦截**（fail-safe）
- 适配器按**能力声明**（domain/ip）分配查询；异常/超时返回 None 不抛异常；维护 `last_error` 供诊断
- **fail-safe 无结论不写检测缓存**（domain_cache/ip_cache）；情报源/融合策略/名单变更必须联动 `threatintel_invalidate()`；**严禁改回无缓存失效的直连查询**
- 在线源分层：**DNSBL 进实时链路**（出厂默认三源 zen/dbl/dronebl；spfbl 邮件评分语义修正后默认停用）；HTTP 类源不预置（方案 C，适配器保留可手工创建，仅测试中心人工核验）；C2 域名情报由 ThreatFox hostfile + C2IntelFeeds（活跃 C2，csv 解析）离线大名单承载
- 离线大名单：整源替换导入、内存缓存匹配；写路径（导入/启停/清空）必须调 `invalidate()` 联动失效内存缓存与统计缓存
- 自动更新各源实际周期 = min(源内置 update_interval_s, 用户全局配置间隔)；调度可视化到期判断口径与此一致
- 日志必录被拦截/剔除请求（filter_log 全字段）；放行日志可选（默认关）+ 采样率控制；写路径走 log_writer 异步批量，**严禁在检测线程内直写 SQLite**
- SQLite 连接线程隔离（db.py threading.local），**严禁模块级单例共享连接**（多源并发导入会报事务冲突）
- dns_server 的 process_query 必须 run_in_executor（同步检测 IO 严禁阻塞 asyncio 事件循环）
- 双进程部署下 Web 改配置经 cross_sync 60s 内生效；测试环境 conftest 设 `DNSF_TESTING=1`（seed 不默认启用在线源）
- 部署：Linux systemd / Docker 为准；Windows 部署仅备用

详见 `AI_AGENTS.md`（AI 开发指引）与 `docs/` 下 PRD V2.1 / 需求说明书 V2.2 / 部署方案。
