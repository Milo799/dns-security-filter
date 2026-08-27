# AI 开发指引（AI_AGENTS.md）

你是本仓库的 AI 开发助手。**先读《docs/Windows DNS 安全过滤中间件 开发PRD V2.0.md》**，再按本指引工作。
本工程已实现 16 轮迭代的全部需求（pytest 205 项全绿），你的任务是**维护与增量开发**：
修 bug、加功能、改需求时同步更新 PRD V2.0 与需求说明书 V2.1，并保证测试持续全绿。

## 1. 仓库心智模型

```
proxy/（Go，纯转发器，一般无需改动；待 Go 环境编译验证）
platform/dns_server.py   ← DNS 报文入口：解析 → 提客户端IP(ECS) → process_query → 回传（支持 A/AAAA/PTR）
platform/detectors.py    ← ★核心：五层检测主流程（白名单→黑名单→离线大名单→在线情报融合→IP 后置过滤）
platform/threat_list.py  ← ★离线大名单：SOURCES 定义、导入/自动更新、内存缓存 O(1) 匹配、
                            镜像降级、统计缓存、next_update_schedule() 调度可视化
platform/auto_update.py  ← 自动更新后台循环：tick = min(用户配置, 各源最小周期)，下限 60s
platform/adapters/       ← 16 个威胁情报适配器（DNSBL/免Key/厂商/URLhaus，三态语义 + last_error）
platform/app/            ← Web 管理：FastAPI 路由（list/threatintel/threatlist/logs/test/config/audit）
platform/seed.py         ← 初始化：建表 + 默认管理员 + 默认配置 + 内置情报源（INSERT OR IGNORE，不覆盖用户配置）
web/index.html           ← 单文件 SPA（SAP Fiori 风格）：拆页黑白名单、情报源表格、测试中心、调度可视化
tests/                   ← 205 项 pytest（跑全部，新增功能必须补测试）
```

## 2. 开发约定（增量改动按依赖关系）

1. **改检测逻辑** → `detectors.py` + 对应测试（`test_fusion/test_reply/test_ptr/test_ecs`）；
2. **改离线大名单** → `threat_list.py`：注意 SOURCES 元数据、`invalidate()` 联动（内存缓存 + `_STATS_CACHE`）、
   `_load_cache()` 有 `_CACHE_LOCK`、`warm_cache()` 由 main.py 启动线程调用；
3. **新增情报源适配器** → `adapters/` 新文件 + `get_adapter_map` 注册 + seed 补内置源 + 测试（参考 urlhaus.py 的三态 + last_error 模式）；
4. **改 Web 接口** → `app/routers/*`：统一响应 `{code,message,data}`、鉴权依赖、audit_log 留痕；
   进度类接口注意多源并发轮询约定（`/import/status` 不带 source 返回全部任务 map）；
5. **改前端** → `web/index.html` 单文件；改完用 node --check 校验内联 JS 语法；
6. **改部署** → `deploy/`（systemd）与 `deploy/docker/`（容器）两套同步改；网络白名单清单在 `deploy/docker/README.md`。

## 3. 必须遵守的约束

- 代理是纯转发器，**不要往 proxy/ 里加检测逻辑**
- EDNS0 OPT RR 必须完整透传，不得剥离
- 平台不缓存 DNS 记录；**A / AAAA / PTR 同等过滤**；拦截应答 A=告警IP、AAAA=空应答，不返回 NXDOMAIN
- 威胁情报**三态语义**：命中→拦截；明确未命中→放行；网络失败/超时/缺 Key→无结论（不参与融合统计）；
  **全部启用源无结论默认拦截**（fail-safe）；适配器异常返回 None 不抛异常，维护 `last_error`
- 适配器按能力声明（domain/ip）分配查询；Key 型源未配 Key 不发请求
- 离线大名单：整源替换导入；写路径（导入/启停/清空）必须调 `invalidate()`；
  各源实际更新周期 = min(源内置 update_interval_s, 用户全局配置间隔)，调度可视化口径与此一致；
  下载容错：连接 15s / 读空闲 30s，GitHub raw 失败降级 jsDelivr 镜像（_MIRROR_RULES）
- 日志：被过滤内容必录（filter_log 全字段）；放行日志受 allow_log_enabled 控制
- api_key 落库加密；密码 bcrypt；接口除 login 外需 Bearer Token
- 数据库结构以 app/schema.sql 为准（新索引用 CREATE IF NOT EXISTS，对已有库自动生效）；扩展需先评审并同步 PRD 第六章

## 4. 验证方式（每次改动后跑）

```bash
cd platform && python -m pytest ../tests -v     # 全部 205 项测试全绿
bash scripts/verify.sh 127.0.0.1 5300 example.com  # 链路通
```

改后端后重启服务：先停净旧进程再启新（旧进程占端口会命中旧代码）。
新增业务后补充测试到 tests/（参考现有写法），并同步更新 docs/ 两份文档。

## 5. 完成标准（当前状态）

- [x] detectors 五层检测主流程全部实现，`make test` 全绿（205 项）
- [x] ECS 客户端 IP 提取验证通过（构造带 ECS 的查询报文测试）
- [x] 16 个威胁情报适配器 + 连通性测试（含 last_error 诊断）
- [x] Web 全部页面可用（登录 → 名单 CRUD → 情报源管理 → 测试中心 → 日志/审计）
- [x] 端到端：配置黑名单/大名单后 dig 恶意域名返回告警 IP，filter_log 可见记录
- [x] 离线大名单：6 内置源 + 自动更新 + 调度可视化 + 页面毫秒级响应
- [x] Docker 化部署 + 网络白名单清单
- [ ] Go 代理层编译验证（开发环境无 Go，需安装后 `go build ./...`）
- [ ] 真实 API Key 联调（微步 / IBM / OTX / GreyNoise / URLhaus Auth-Key 等，待用户提供 Key）
