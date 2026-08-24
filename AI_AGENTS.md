# AI 开发指引（AI_AGENTS.md）

你是本仓库的 AI 开发助手。**先读《docs/Windows DNS 安全过滤中间件 开发PRD V1.2.md》**，再按本指引工作。
本骨架已完成工程搭设与最小闭环，你的任务是**按 TODO 填空并保证测试通过**，不是重新设计。

## 1. 仓库心智模型

```
proxy/（Go，已完成，一般无需改动）
platform/dns_server.py  ← DNS 报文入口：解析 → 提客户端IP(ECS) → process_query → 回传
platform/detectors.py   ← ★核心：检测主流程，7 个 TODO 待实现
platform/adapters/      ← 威胁情报适配器框架（接口已定）
platform/app/           ← Web 管理：FastAPI 路由全部已声明，返回占位（TODO 实现）
platform/seed.py        ← 初始化：建表 + 默认管理员 + 默认配置（已完成）
tests/                  ← 锚点测试（已通过）+ 你补充的业务测试
```

## 2. 开发顺序建议（按依赖关系）

1. **detectors.py 主流程**（最核心）——实现后平台才能"过滤"：
   - `match_list` / `is_whitelisted` / `is_blacklisted`（名单匹配，SQLite 数据在 app/db.get_enabled_list）
   - `query_upstream` / `query_upstream_reply`（公网解析，dnslib 向 CONFIG.upstream_dns 查询）
   - `ip_postfilter`（IP 黑名单 + 威胁情报融合）
   - `query_threatintel_domain` / `query_threatintel_ip`（多源融合，复用 adapters.run_fusion）
   - `write_filter_log` / `write_allow_log`（写 filter_log 表）
2. **dns_server.extract_client_ip**——按 RFC 7871 解析 EDNS0 Client Subnet（opt code 8），返回客户端 IP
3. **adapters/get_enabled_adapters + 1 个真实情报源适配器**（如 VirusTotal 免费接口）
4. **app/routers/* 各 TODO**——把占位响应换成真实 CRUD（注意统一响应 `{code,message,data}`、鉴权依赖、audit_log 留痕）
5. **web/**——按 PRD 5.6 页面清单搭建前端（Vue3 + Vite 或原生 HTML，调用 /api）
6. **deploy/install.sh 完善**——构建产物、依赖安装、配置落位

## 3. 必须遵守的约束

- 代理是纯转发器，**不要往 proxy/ 里加检测逻辑**
- EDNS0 OPT RR 必须完整透传，不得剥离
- 平台不缓存 DNS 记录
- A/AAAA 同等过滤；拦截应答 A=告警IP、AAAA=空应答，不返回 NXDOMAIN
- 威胁情报适配器：异常/超时返回 None 不抛异常；全部源超时默认拦截
- 日志：被过滤内容必录（filter_log 全字段）；放行日志受 allow_log_enabled 控制
- api_key 落库加密；密码 bcrypt；接口除 login 外需 Bearer Token
- 数据库结构以 app/schema.sql 为准，扩展需先评审

## 4. 验证方式（每次改动后跑）

```bash
cd platform && python -m pytest ../tests -v     # 锚点测试全绿
bash scripts/verify.sh 127.0.0.1 5300 example.com  # 链路通
```

新增业务后补充测试到 tests/（参考现有锚点写法）。

## 5. 完成标准

- [ ] detectors 全部 TODO 实现，`make test` 全绿
- [ ] ECS 客户端 IP 提取验证通过（构造带 ECS 的查询报文测试）
- [ ] 至少 1 个真实威胁情报源适配器 + 连通性测试
- [ ] Web 全部接口可用（登录 → 名单 CRUD → 日志查询）
- [ ] 端到端：配置黑名单后 dig 恶意域名返回告警 IP，filter_log 可见记录
