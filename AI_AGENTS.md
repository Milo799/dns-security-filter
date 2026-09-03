# AI 开发指引（AI_AGENTS.md）

你是本仓库的 AI 开发助手。**先读《docs/Windows DNS 安全过滤中间件 开发PRD V2.1.md》**，再按本指引工作。
本工程已实现 22 轮迭代的全部需求（pytest 278 项全绿），你的任务是**维护与增量开发**：
修 bug、加功能、改需求时同步更新 PRD V2.1 与需求说明书 V2.2，并保证测试持续全绿。

## 1. 仓库心智模型

```
proxy/（Go，纯转发器；已编译验证 + 端到端四场景通过，一般无需改动）
platform/dns_server.py   ← DNS 报文入口：解析 → 提客户端IP(ECS) → process_query（run_in_executor）→ 回传
platform/detectors.py    ← ★核心：五层检测主流程（白名单→黑名单→大名单→在线情报融合→IP 后置并行）
                            + domain_cache/ip_cache 结论缓存 + 单次上游往返（_extract_ips）
platform/domain_cache.py ← 域名结论缓存（LRU+TTL，fail-safe 不缓存，threatintel_invalidate 联动）
platform/ip_cache.py     ← IP 结论缓存（与 domain_cache 同构；TTL 900s/容量 20 万）
platform/threat_list.py  ← ★离线大名单：SOURCES 定义、导入/自动更新、内存缓存 O(1) 匹配、
                            镜像降级、统计缓存、next_update_schedule() 调度可视化
platform/auto_update.py  ← 自动更新后台循环：tick = min(用户配置, 各源最小周期)，下限 60s
platform/circuit_breaker.py ← 单源限流熔断降级（连续失败熔断/半开恢复）
platform/log_writer.py   ← 日志异步批量写入（内存队列削峰；/api/log-writer/stats 观测）
platform/log_retention.py ← 日志保留期清理（每 6h 分批删 filter_log/audit_log 过期行；/api/log-retention/stats）
platform/cross_sync.py   ← 跨进程同步：DNS 进程 60s 轮询四表 MAX(updated_at)（双进程部署热生效）
platform/adapters/       ← 16 个威胁情报适配器（DNSBL/免Key/厂商/URLhaus，三态语义 + last_error）
platform/app/            ← Web 管理：FastAPI 路由（list/threatintel/threatlist/logs/test/config/audit）
platform/app/crypto.py   ← api_key 落库 Fernet 加密（密钥由 jwt_secret 派生；存量明文启动自动迁移）
platform/seed.py         ← 初始化：建表 + 默认管理员 + 默认配置 + 内置情报源（默认仅启用 DNSBL 三源 zen/dbl/dronebl；
                            spfbl 语义修正后默认停用；九个 HTTP 源已退役不预置，存量库启动自动清理迁移；
                            DNSF_TESTING=1 时不启用任何在线源——单测隔离用）
web/index.html + css/ + js/ ← 多文件 SPA（零构建链）：css/{theme,base,pages} + js/{app,charts,boot}
                            + js/pages/×9（dashboard/logs/lists/testcenter/threatintel/threatlist/
                            fusion/config/audit）；加载顺序固定：app → charts → pages/* → boot；
                            页面模块末尾 PAGE_LOADERS.xxx = loadXxx 注册
tools/loadtest.py        ← DNS 压测（QPS/延迟分位；Windows 须 SelectorEventLoop）
tests/                   ← 310 项 pytest（跑全部，新增功能必须补测试；conftest 已设 DNSF_TESTING=1）
```

## 2. 开发约定（增量改动按依赖关系）

1. **改检测逻辑** → `detectors.py` + 对应测试（`test_fusion/test_reply/test_ptr/test_ecs/test_perf_optimize`）；
   注意：fail-safe 无结论不写缓存；情报源/融合策略变更联动 domain_cache+ip_cache 的 `threatintel_invalidate()`；
   IP 后置须并行（先本地黑名单/大名单内存查，再线程池查在线源）；全正常路径返回上游原始应答；
2. **改离线大名单** → `threat_list.py`：注意 SOURCES 元数据、`invalidate()` 联动（内存缓存 + `_STATS_CACHE`）、
   `_load_cache()` 有 `_CACHE_LOCK`、`warm_cache()` 由 main.py 启动线程调用；
3. **新增情报源适配器** → `adapters/` 新文件 + `get_adapter_map` 注册 + 测试（参考 urlhaus.py 的三态 + last_error 模式）；
   方案 C 后 seed 不再预置新 HTTP 源（内置仅 DNSBL 四源：zen/dbl/dronebl 默认启用 + spfbl 默认停用），
   需要预置时须评审并同步三处文档；
4. **改 Web 接口** → `app/routers/*`：统一响应 `{code,message,data}`、鉴权依赖、audit_log 留痕；
   进度类接口注意多源并发轮询约定（`/import/status` 不带 source 返回全部任务 map）；
5. **改前端** → `web/` 多文件：页面逻辑进 `js/pages/<page>.js`（末尾注册 PAGE_LOADERS），页面独有样式进
   `css/pages.css`；改完用 node --check 校验 JS 语法；静态交叉检查（HTML onclick ↔ JS 顶层函数、
   getElementById ↔ HTML id）；
6. **改部署** → `deploy/`（systemd + 一键脚本）与 `deploy/docker/`（容器）两套同步改；网络白名单清单在 `deploy/docker/README.md`；
7. **改配置项** → `config.py` 默认值 + `app/runtime.py` _INT_KEYS + `app/routers/config.py` 校验 +
   `platform.example.yaml` 注释项，四处对齐。

## 3. 必须遵守的约束

- 代理是纯转发器，**不要往 proxy/ 里加检测逻辑**
- EDNS0 OPT RR 必须完整透传，不得剥离
- 平台不缓存 DNS 记录（结论缓存只缓存情报判定，不缓存 DNS 应答）；**A / AAAA / PTR 同等过滤**；
  拦截应答 A=告警IP、AAAA=空应答，不返回 NXDOMAIN
- 威胁情报**三态语义**：命中→拦截；明确未命中→放行；网络失败/超时/缺 Key→无结论（不参与融合统计）；
  **全部启用源无结论默认拦截**（fail-safe）；适配器异常返回 None 不抛异常，维护 `last_error`
- 适配器按能力声明（domain/ip）分配查询；Key 型源未配 Key 不发请求
- **在线源分层**：DNSBL（DNS 协议）进实时检测链路（出厂默认三源 zen/dbl/dronebl，spfbl 默认停用可选）；
  HTTP 类源不进实时链路（方案 C 后不预置，手工创建后仅测试中心人工核验），
  避免秒级延迟与免费 Key 配额打满
- **fail-safe 无结论不写检测缓存**；缓存命中直接返回结论；变更必须联动失效（严禁删除 invalidate 调用）
- 离线大名单：整源替换导入；写路径（导入/启停/清空）必须调 `invalidate()`；
  各源实际更新周期 = min(源内置 update_interval_s, 用户全局配置间隔)，调度可视化口径与此一致；
  下载容错：连接 15s / 读空闲 30s，GitHub raw 失败降级 jsDelivr 镜像（_MIRROR_RULES）
- 日志：被过滤内容必录（filter_log 全字段）；放行日志受 allow_log_enabled + allow_log_sample_rate 控制；
  写入必须走 log_writer 异步批量，**严禁在检测线程直写 SQLite**；保留期清理走 log_retention 后台线程
- **SQLite 连接线程隔离**（db.py threading.local + busy_timeout 30s），严禁模块级单例共享连接
  （多源并发导入会报 "cannot start a transaction within a transaction"）
- dns_server 的 process_query 必须 run_in_executor（同步检测 IO 严禁直调 asyncio 事件循环，会卡死全部并发查询）
- 双进程部署：Web 进程改配置 → DNS 进程经 cross_sync 60s 轮询生效；改四表任何写路径必须更新 updated_at
- **api_key 落库加密**（app/crypto.py Fernet，密钥由 jwt_secret 派生）：写入必须 encrypt_key、
  读取必须 decrypt_key（勿直接读 threatintel_api.api_key 列）；密码 bcrypt；接口除 login 外需 Bearer Token
- 数据库结构以 app/schema.sql 为准（新索引用 CREATE IF NOT EXISTS，对已有库自动生效）；扩展需先评审并同步 PRD 第六章

## 4. 验证方式（每次改动后跑）

```bash
cd platform && python -m pytest ../tests -v     # 全部 278 项测试全绿
bash scripts/verify.sh 127.0.0.1 5300 example.com  # 链路通
python tools/loadtest.py 127.0.0.1 --qps 1000   # 压测（改动性能路径时）
```

改后端后重启服务：先停净旧进程再启新（旧进程占端口会命中旧代码）。
新增业务后补充测试到 tests/（参考现有写法），并同步更新 docs/ 两份文档。

## 5. 完成标准（当前状态）

- [x] detectors 五层检测主流程全部实现，`make test` 全绿（278 项）
- [x] ECS 客户端 IP 提取验证通过（构造带 ECS 的查询报文测试）
- [x] 16 个威胁情报适配器 + 连通性测试（含 last_error 诊断）+ 单源熔断
- [x] Web 全部页面可用（登录 → 大屏 → 人工情报源双 Tab → 情报源管理 → 测试中心 → 日志/审计）
- [x] 端到端：配置黑名单/大名单后 dig 恶意域名返回告警 IP，filter_log 可见记录
- [x] 离线大名单：6 内置源 + 自动更新 + 调度可视化 + 页面毫秒级响应
- [x] Docker 化部署 + 网络白名单清单 + 一键部署脚本（install-proxy.sh / install-platform.sh）
- [x] Go 代理层编译验证 + 端到端四场景（放行/拦截/SERVFAIL 容灾/ECS 透传）
- [x] 10 万终端前置五项（结论缓存/熔断/压测/采样/削峰）+ 解析速度优化五项（IP 缓存/DNSBL 默认/
      IP 并行/单次上游往返/跨进程同步）——实测 1000QPS P95=1.86ms、检测路径缓存命中 12ms
- [ ] 真实 API Key 联调（微步 / IBM / OTX / GreyNoise / URLhaus Auth-Key 等，待用户提供 Key）
